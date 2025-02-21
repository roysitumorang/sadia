package query

import (
	"context"
	"errors"
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
	if filter.ConfirmationToken != "" {
		params = append(params, filter.ConfirmationToken)
		builder.Reset()
		_, _ = builder.WriteString("confirmation_token = $")
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
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
		, confirmation_token
		, confirmed_at
		, email
		, unconfirmed_email
		, email_confirmation_token
		, email_confirmation_sent_at
		, email_confirmed_at
		, phone
		, unconfirmed_phone
		, phone_confirmation_token
		, phone_confirmation_sent_at
		, phone_confirmed_at
		, encrypted_password
		, last_password_change
		, reset_password_token
		, reset_password_sent_at
		, login_count
		, current_login_at
		, current_login_ip
		, last_login_at
		, last_login_ip
		, login_failed_attempts
		, login_unlock_token
		, login_locked_at
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
			&account.ConfirmationToken,
			&account.ConfirmedAt,
			&account.Email,
			&account.UnconfirmedEmail,
			&account.EmailConfirmationToken,
			&account.EmailConfirmationSentAt,
			&account.EmailConfirmedAt,
			&account.Phone,
			&account.UnconfirmedPhone,
			&account.PhoneConfirmationToken,
			&account.PhoneConfirmationSentAt,
			&account.PhoneConfirmedAt,
			&account.EncryptedPassword,
			&account.LastPasswordChange,
			&account.ResetPasswordToken,
			&account.ResetPasswordSentAt,
			&account.LoginCount,
			&account.CurrentLoginAt,
			&account.CurrentLoginIP,
			&account.LastLoginAt,
			&account.LastLoginIP,
			&account.LoginFailedAttempts,
			&account.LoginUnlockToken,
			&account.LoginLockedAt,
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
		confirmationToken, emailToken, phoneToken := helper.RandomString(32), helper.RandomString(32), helper.RandomNumber(6)
		var emailConfirmationToken,
			phoneConfirmationToken *string
		if request.Email != nil {
			emailConfirmationToken = &emailToken
		}
		if request.Phone != nil {
			phoneConfirmationToken = &phoneToken
		}
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
				, confirmation_token
				, unconfirmed_email
				, email_confirmation_token
				, unconfirmed_phone
				, phone_confirmation_token
				, created_by
				, created_at
				, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13)
			RETURNING id
				, uid
				, account_type
				, status
				, name
				, username
				, confirmation_token
				, confirmed_at
				, email
				, unconfirmed_email
				, email_confirmation_token
				, email_confirmation_sent_at
				, email_confirmed_at
				, phone
				, unconfirmed_phone
				, phone_confirmation_token
				, phone_confirmation_sent_at
				, phone_confirmed_at
				, encrypted_password
				, last_password_change
				, reset_password_token
				, reset_password_sent_at
				, login_count
				, current_login_at
				, current_login_ip
				, last_login_at
				, last_login_ip
				, login_failed_attempts
				, login_unlock_token
				, login_locked_at
				, created_by
				, created_at
				, updated_at
				, deactivated_by
				, deactivated_at
				, deactivation_reason`,
			accountID,
			accountUID,
			request.AccountType,
			accountModel.StatusUnconfirmed,
			request.Name,
			request.Username,
			confirmationToken,
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
			&response.ConfirmationToken,
			&response.ConfirmedAt,
			&response.Email,
			&response.UnconfirmedEmail,
			&response.EmailConfirmationToken,
			&response.EmailConfirmationSentAt,
			&response.EmailConfirmedAt,
			&response.Phone,
			&response.UnconfirmedPhone,
			&response.PhoneConfirmationToken,
			&response.PhoneConfirmationSentAt,
			&response.PhoneConfirmedAt,
			&response.EncryptedPassword,
			&response.LastPasswordChange,
			&response.ResetPasswordToken,
			&response.ResetPasswordSentAt,
			&response.LoginCount,
			&response.CurrentLoginAt,
			&response.CurrentLoginIP,
			&response.LastLoginAt,
			&response.LastLoginIP,
			&response.LoginFailedAttempts,
			&response.LoginUnlockToken,
			&response.LoginLockedAt,
			&response.CreatedBy,
			&response.CreatedAt,
			&response.UpdatedAt,
			&response.DeactivatedBy,
			&response.DeactivatedAt,
			&response.DeactivationReason,
		); err != nil {
			var pgxErr *pgconn.PgError
			if errors.As(err, &pgxErr) &&
				pgxErr.Code == pgerrcode.UniqueViolation {
				switch pgxErr.ConstraintName {
				case "accounts_username_key":
					err = accountModel.ErrUniqueUsernameViolation
				case "accounts_email_key":
					err = accountModel.ErrUniqueEmailViolation
				case "accounts_phone_key":
					err = accountModel.ErrUniquePhoneViolation
				case "accounts_confirmation_token_key":
					err = accountModel.ErrUniqueConfirmationTokenViolation
					continue
				case "accounts_email_confirmation_token_key":
					err = accountModel.ErrUniqueEmailConfirmationTokenViolation
					continue
				case "accounts_phone_confirmation_token_key":
					err = accountModel.ErrUniquePhoneConfirmationTokenViolation
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
			, confirmation_token = $5
			, email = $6
			, unconfirmed_email = $7
			, email_confirmation_token = $8
			, email_confirmation_sent_at = $9
			, email_confirmed_at = $10
			, phone = $11
			, unconfirmed_phone = $12
			, phone_confirmation_token = $13
			, phone_confirmation_sent_at = $14
			, phone_confirmed_at = $15
			, encrypted_password = $16
			, last_password_change = $17
			, reset_password_token = $18
			, reset_password_sent_at = $19
			, login_count = $20
			, current_login_at = $21
			, current_login_ip = $22
			, last_login_at = $23
			, last_login_ip = $24
			, login_failed_attempts = $25
			, login_unlock_token = $26
			, login_locked_at = $27
			, updated_at = $28
			, deactivated_by = $29
			, deactivated_at = $30
			, deactivation_reason = $31
		WHERE id = $32
		RETURNING id
			, uid
			, account_type
			, status
			, name
			, username
			, confirmation_token
			, confirmed_at
			, email
			, unconfirmed_email
			, email_confirmation_token
			, email_confirmation_sent_at
			, email_confirmed_at
			, phone
			, unconfirmed_phone
			, phone_confirmation_token
			, phone_confirmation_sent_at
			, phone_confirmed_at
			, encrypted_password
			, last_password_change
			, reset_password_token
			, reset_password_sent_at
			, login_count
			, current_login_at
			, current_login_ip
			, last_login_at
			, last_login_ip
			, login_failed_attempts
			, login_unlock_token
			, login_locked_at
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
		request.ConfirmationToken,
		request.Email,
		request.UnconfirmedEmail,
		request.EmailConfirmationToken,
		request.EmailConfirmationSentAt,
		request.EmailConfirmedAt,
		request.Phone,
		request.UnconfirmedPhone,
		request.PhoneConfirmationToken,
		request.PhoneConfirmationSentAt,
		request.PhoneConfirmedAt,
		request.EncryptedPassword,
		request.LastPasswordChange,
		request.ResetPasswordToken,
		request.ResetPasswordSentAt,
		request.LoginCount,
		request.CurrentLoginAt,
		request.CurrentLoginIP,
		request.LastLoginAt,
		request.LastLoginIP,
		request.LoginFailedAttempts,
		request.LoginUnlockToken,
		request.LoginLockedAt,
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
		&request.ConfirmationToken,
		&request.ConfirmedAt,
		&request.Email,
		&request.UnconfirmedEmail,
		&request.EmailConfirmationToken,
		&request.EmailConfirmationSentAt,
		&request.EmailConfirmedAt,
		&request.Phone,
		&request.UnconfirmedPhone,
		&request.PhoneConfirmationToken,
		&request.PhoneConfirmationSentAt,
		&request.PhoneConfirmedAt,
		&request.EncryptedPassword,
		&request.LastPasswordChange,
		&request.ResetPasswordToken,
		&request.ResetPasswordSentAt,
		&request.LoginCount,
		&request.CurrentLoginAt,
		&request.CurrentLoginIP,
		&request.LastLoginAt,
		&request.LastLoginIP,
		&request.LoginFailedAttempts,
		&request.LoginUnlockToken,
		&request.LoginLockedAt,
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
		var pgxErr *pgconn.PgError
		if errors.As(err, &pgxErr) &&
			pgxErr.Code == pgerrcode.UniqueViolation {
			switch pgxErr.ConstraintName {
			case "accounts_username_key":
				err = accountModel.ErrUniqueUsernameViolation
			case "accounts_email_key":
				err = accountModel.ErrUniqueEmailViolation
			case "accounts_phone_key":
				err = accountModel.ErrUniquePhoneViolation
			case "accounts_confirmation_token_key":
				err = accountModel.ErrUniqueConfirmationTokenViolation
			case "accounts_email_confirmation_token_key":
				err = accountModel.ErrUniqueEmailConfirmationTokenViolation
			case "accounts_phone_confirmation_token_key":
				err = accountModel.ErrUniquePhoneConfirmationTokenViolation
			}
		} else {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		}
	}
	return err
}
