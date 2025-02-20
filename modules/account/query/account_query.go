package query

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/govalues/decimal"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/roysitumorang/sadia/helper"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	"go.uber.org/zap"
)

type (
	accountQuery struct {
		dbRead,
		dbWrite *pgxpool.Pool
	}
)

func New(
	dbRead,
	dbWrite *pgxpool.Pool,
) AccountQuery {
	return &accountQuery{
		dbRead:  dbRead,
		dbWrite: dbWrite,
	}
}

func (q *accountQuery) BeginTx(ctx context.Context) (pgx.Tx, error) {
	ctxt := "AccountQuery-BeginTx"
	tx, err := q.dbWrite.Begin(ctx)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrBegin")
	}
	return tx, err
}

func (q *accountQuery) FindAccounts(ctx context.Context, filter *accountModel.Filter) ([]*accountModel.Account, int64, int64, error) {
	ctxt := "AccountQuery-FindAccounts"
	var (
		params     []interface{}
		conditions []string
		builder    strings.Builder
	)
	if filter.Login != "" {
		params = append(params, filter.Login)
		n := strconv.Itoa(len(params))
		builder.Reset()
		_, _ = builder.WriteString("(uid = $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR username = $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR email = $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR phone = $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	if len(filter.AccountUIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("uid IN (")
		for i, accountID := range filter.AccountUIDs {
			params = append(params, accountID)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	if filter.Keyword != "" {
		builder.Reset()
		_, _ = builder.WriteString("%%")
		_, _ = builder.WriteString(strings.ToLower(filter.Keyword))
		_, _ = builder.WriteString("%%")
		params = append(params, builder.String())
		n := strconv.Itoa(len(params))
		builder.Reset()
		_, _ = builder.WriteString("(LOWER(name) LIKE $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR username LIKE $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR email LIKE $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR phone LIKE $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	if len(filter.StatusList) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("status IN (")
		for i, status := range filter.StatusList {
			params = append(params, status)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	builder.Reset()
	_, _ = builder.WriteString(
		`SELECT COUNT(1)
		FROM accounts`,
	)
	if len(conditions) > 0 {
		_, _ = builder.WriteString(" WHERE")
		for i, condition := range conditions {
			if i > 0 {
				_, _ = builder.WriteString(" AND")
			}
			_, _ = builder.WriteString(" ")
			_, _ = builder.WriteString(condition)
		}
	}
	query := builder.String()
	var total int64
	err := q.dbRead.QueryRow(ctx, query, params...).Scan(&total)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
		return nil, 0, 0, err
	}
	if total == 0 {
		return nil, 0, 0, nil
	}
	query = strings.ReplaceAll(
		query,
		"COUNT(1)",
		`id
		, uid
		, account_type
		, status
		, name
		, username
		, email
		, unconfirmed_email
		, email_confirmation_token
		, email_confirmed_at
		, phone
		, unconfirmed_phone
		, phone_confirmation_token
		, phone_confirmed_at
		, encrypted_password
		, password_reset_token
		, login_count
		, current_login_at
		, current_login_ip
		, last_login_at
		, last_login_ip
		, created_by
		, created_at
		, updated_at
		, deactivated_by
		, deactivated_at
		, deactivation_reason`,
	)
	builder.Reset()
	_, _ = builder.WriteString(query)
	_, _ = builder.WriteString(" ORDER by -id")
	pages := int64(1)
	if filter.Limit > 0 {
		totalDecimal, err := decimal.New(total, 0)
		if err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrNew")
			return nil, 0, 0, err
		}
		perPageDecimal, err := decimal.New(filter.Limit, 0)
		if err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrNew")
			return nil, 0, 0, err
		}
		pagesDecimal, err := totalDecimal.Quo(perPageDecimal)
		if err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrQuo")
			return nil, 0, 0, err
		}
		pages, _, _ = pagesDecimal.Ceil(0).Int64(0)
		offset := (filter.Page - 1) * filter.Limit
		_, _ = builder.WriteString(" LIMIT ")
		_, _ = builder.WriteString(strconv.FormatInt(filter.Limit, 10))
		_, _ = builder.WriteString(" OFFSET ")
		_, _ = builder.WriteString(strconv.FormatInt(offset, 10))
	}
	rows, err := q.dbRead.Query(ctx, builder.String(), params...)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrQuery")
		return nil, 0, 0, err
	}
	defer rows.Close()
	var response []*accountModel.Account
	for rows.Next() {
		var account accountModel.Account
		if err = rows.Scan(
			&account.ID,
			&account.UID,
			&account.AccountType,
			&account.Status,
			&account.Name,
			&account.Username,
			&account.Email,
			&account.UnconfirmedEmail,
			&account.EmailConfirmationToken,
			&account.EmailConfirmedAt,
			&account.Phone,
			&account.UnconfirmedPhone,
			&account.PhoneConfirmationToken,
			&account.PhoneConfirmedAt,
			&account.EncryptedPassword,
			&account.PasswordResetToken,
			&account.LoginCount,
			&account.CurrentLoginAt,
			&account.CurrentLoginIP,
			&account.LastLoginAt,
			&account.LastLoginIP,
			&account.CreatedBy,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.DeactivatedBy,
			&account.DeactivatedAt,
			&account.DeactivationReason,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, 0, 0, err
		}
		response = append(response, &account)
	}
	return response, total, pages, nil

}
func (q *accountQuery) CreateAccount(ctx context.Context, request *accountModel.NewAccount) (*accountModel.Account, error) {
	ctxt := "AccountQuery-CreateAccount"
	var response accountModel.Account
	for {
		accountID, accountUID, _, err := helper.GenerateUniqueID()
		if err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrGenerateUniqueID")
			continue
		}
		var emailConfirmationToken *string
		if request.Email != nil {
			token := helper.RandomString(32)
			emailConfirmationToken = &token
		}
		phoneConfirmationToken := helper.RandomNumber(6)
		now := time.Now()
		if err = q.dbWrite.QueryRow(
			ctx,
			`INSERT INTO accounts (
				id
				, uid
				, account_type
				, status
				, name
				, username
				, email
				, email_confirmation_token
				, phone
				, phone_confirmation_token
				, created_by
				, created_at
				, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12)
			RETURNING id
				, uid
				, account_type
				, status
				, name
				, username
				, email
				, unconfirmed_email
				, email_confirmation_token
				, email_confirmed_at
				, phone
				, unconfirmed_phone
				, phone_confirmation_token
				, phone_confirmed_at
				, encrypted_password
				, password_reset_token
				, login_count
				, current_login_at
				, current_login_ip
				, last_login_at
				, last_login_ip
				, created_at
				, updated_at
				, deactivated_at
				, deactivation_reason`,
			accountID,
			accountUID,
			request.AccountType,
			accountModel.StatusUnconfirmed,
			request.Name,
			request.Username,
			request.Email,
			emailConfirmationToken,
			request.Phone,
			phoneConfirmationToken,
			request.CreatedBy,
			now,
		).Scan(
			&response.ID,
			&response.UID,
			&response.AccountType,
			&response.Status,
			&response.Name,
			&response.Username,
			&response.Email,
			&response.UnconfirmedEmail,
			&response.EmailConfirmationToken,
			&response.EmailConfirmedAt,
			&response.Phone,
			&response.UnconfirmedPhone,
			&response.PhoneConfirmationToken,
			&response.PhoneConfirmedAt,
			&response.EncryptedPassword,
			&response.PasswordResetToken,
			&response.LoginCount,
			&response.CurrentLoginAt,
			&response.CurrentLoginIP,
			&response.LastLoginAt,
			&response.LastLoginIP,
			&response.CreatedAt,
			&response.UpdatedAt,
			&response.DeactivatedAt,
			&response.DeactivationReason,
		); err != nil {
			var pgxErr *pgconn.PgError
			if errors.As(err, &pgxErr) &&
				pgxErr.Code == pgerrcode.UniqueViolation {
				switch pgxErr.ConstraintName {
				case "accounts_username_key":
					err = fmt.Errorf("username: %s already exists", request.Username)
				case "accounts_email_key":
					err = fmt.Errorf("email: %s already exists", *request.Email)
				case "accounts_phone_key":
					err = fmt.Errorf("phone: %s already exists", request.Phone)
				case "accounts_email_confirmation_token_key",
					"accounts_phone_confirmation_token_key":
					continue
				}
			} else {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			}
			return nil, err
		}
		break
	}
	return &response, nil
}

func (q *accountQuery) UpdateAccount(ctx context.Context, tx pgx.Tx, request *accountModel.Account) error {
	ctxt := "AccountQuery-UpdateAccount"
	err := tx.QueryRow(
		ctx,
		`UPDATE accounts SET
			account_type = $1
			, status = $2
			, name = $3
			, username = $4
			, email = $5
			, unconfirmed_email = $6
			, email_confirmation_token = $7
			, email_confirmed_at = $8
			, phone = $9
			, unconfirmed_phone = $10
			, phone_confirmation_token = $11
			, phone_confirmed_at = $12
			, encrypted_password = $13
			, password_reset_token = $14
			, login_count = $15
			, current_login_at = $16
			, current_login_ip = $17
			, last_login_at = $18
			, last_login_ip = $19
			, updated_at = $20
			, deactivated_by = $21
			, deactivated_at = $22
			, deactivation_reason = $23
		WHERE id = $24
		RETURNING id
			, uid
			, account_type
			, status
			, name
			, username
			, email
			, unconfirmed_email
			, email_confirmation_token
			, email_confirmed_at
			, phone
			, unconfirmed_phone
			, phone_confirmation_token
			, phone_confirmed_at
			, encrypted_password
			, password_reset_token
			, login_count
			, current_login_at
			, current_login_ip
			, last_login_at
			, last_login_ip
			, created_by
			, created_at
			, updated_at
			, deactivated_by
			, deactivated_at
			, deactivation_reason`,
		request.AccountType,
		request.Status,
		request.Name,
		request.Username,
		request.Email,
		request.UnconfirmedEmail,
		request.EmailConfirmationToken,
		request.EmailConfirmedAt,
		request.Phone,
		request.UnconfirmedPhone,
		request.PhoneConfirmationToken,
		request.PhoneConfirmedAt,
		request.EncryptedPassword,
		request.PasswordResetToken,
		request.LoginCount,
		request.CurrentLoginAt,
		request.CurrentLoginIP,
		request.LastLoginAt,
		request.LastLoginIP,
		request.UpdatedAt,
		request.DeactivatedBy,
		request.DeactivatedAt,
		request.DeactivationReason,
		request.ID,
	).Scan(
		&request.ID,
		&request.UID,
		&request.AccountType,
		&request.Status,
		&request.Name,
		&request.Username,
		&request.Email,
		&request.UnconfirmedEmail,
		&request.EmailConfirmationToken,
		&request.EmailConfirmedAt,
		&request.Phone,
		&request.UnconfirmedPhone,
		&request.PhoneConfirmationToken,
		&request.PhoneConfirmedAt,
		&request.EncryptedPassword,
		&request.PasswordResetToken,
		&request.LoginCount,
		&request.CurrentLoginAt,
		&request.CurrentLoginIP,
		&request.LastLoginAt,
		&request.LastLoginIP,
		&request.CreatedBy,
		&request.CreatedAt,
		&request.UpdatedAt,
		&request.DeactivatedBy,
		&request.DeactivatedAt,
		&request.DeactivationReason,
	)
	if err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
	}
	return err
}
