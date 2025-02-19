package query

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/govalues/decimal"
	"github.com/jackc/pgx/v5"
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
		_, _ = builder.WriteString("(username = $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR email = $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR phone = $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	if len(filter.AccountIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("id IN (")
		for i, accountID := range filter.AccountIDs {
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
		, pid
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
	)
	builder.Reset()
	_, _ = builder.WriteString(query)
	_, _ = builder.WriteString(" ORDER by -id")
	pages := int64(1)
	if filter.PerPage > 0 {
		totalDecimal, err := decimal.New(total, 0)
		if err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrNew")
			return nil, 0, 0, err
		}
		perPageDecimal, err := decimal.New(filter.PerPage, 0)
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
		offset := (filter.Page - 1) * filter.PerPage
		_, _ = builder.WriteString(" LIMIT ")
		_, _ = builder.WriteString(strconv.FormatInt(filter.PerPage, 10))
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
			&account.PID,
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
			&account.CreatedAt,
			&account.UpdatedAt,
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
			, deactivated_at = $21
			, deactivation_reason = $22
		WHERE id = $23
		RETURNING id
			, pid
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
		request.DeactivatedAt,
		request.DeactivationReason,
		request.ID,
	).Scan(
		&request.ID,
		&request.PID,
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
		&request.CreatedAt,
		&request.UpdatedAt,
		&request.DeactivatedAt,
		&request.DeactivationReason,
	)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
	}
	return err
}
