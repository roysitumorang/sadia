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
	"github.com/roysitumorang/sadia/models"
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

func (q *accountQuery) FindAccounts(ctx context.Context, filter *accountModel.Filter) ([]*accountModel.Account, int64, int64, error) {
	ctxt := "AccountQuery-FindAccounts"
	var (
		params     []any
		conditions []string
		builder    strings.Builder
	)
	if len(filter.AccountIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("a.id IN (")
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
	if len(filter.CompanyIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString(
			`EXISTS(
				SELECT 1
				FROM users u
				WHERE u.account_id = a.id
					AND u.company_id IN (`,
		)
		for i, companyID := range filter.CompanyIDs {
			params = append(params, companyID)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString("))")
		conditions = append(conditions, builder.String())
	}
	if len(filter.StatusList) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("a.status IN (")
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
	if len(filter.AccountTypes) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("a.account_type IN (")
		for i, accountType := range filter.AccountTypes {
			params = append(params, accountType)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	if len(filter.AdminLevels) > 0 {
		builder.Reset()
		_, _ = builder.WriteString(
			`EXISTS(
				SELECT 1
				FROM admins ad
				WHERE ad.account_id = a.id
					AND ad.admin_level IN (`,
		)
		for i, adminLevel := range filter.AdminLevels {
			params = append(params, adminLevel)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString("))")
		conditions = append(conditions, builder.String())
	}
	if len(filter.UserLevels) > 0 {
		builder.Reset()
		_, _ = builder.WriteString(
			`EXISTS(
				SELECT 1
				FROM users u
				WHERE u.account_id = a.id
					AND u.user_level IN (`,
		)
		for i, userLevel := range filter.UserLevels {
			params = append(params, userLevel)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString("))")
		conditions = append(conditions, builder.String())
	}
	if filter.Login != "" {
		params = append(params, filter.Login)
		n := strconv.Itoa(len(params))
		builder.Reset()
		_, _ = builder.WriteString("(a.id = $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR a.username = $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR a.email = $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR a.phone = $")
		_, _ = builder.WriteString(n)
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
		_, _ = builder.WriteString("(LOWER(a.name) LIKE $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR a.username LIKE $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR a.email LIKE $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR a.phone LIKE $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	if filter.Username != "" {
		params = append(params, filter.Username)
		builder.Reset()
		_, _ = builder.WriteString("a.username = $")
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
		conditions = append(conditions, builder.String())
	}
	if filter.ConfirmationToken != "" {
		params = append(params, filter.ConfirmationToken)
		builder.Reset()
		_, _ = builder.WriteString("a.confirmation_token = $")
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
		conditions = append(conditions, builder.String())
	}
	if filter.Email != "" {
		params = append(params, filter.Email)
		builder.Reset()
		_, _ = builder.WriteString("a.email = $")
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
		conditions = append(conditions, builder.String())
	}
	if filter.EmailConfirmationToken != "" {
		params = append(params, filter.EmailConfirmationToken)
		builder.Reset()
		_, _ = builder.WriteString("a.email_confirmation_token = $")
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
		conditions = append(conditions, builder.String())
	}
	if filter.Phone != "" {
		params = append(params, filter.Phone)
		builder.Reset()
		_, _ = builder.WriteString("a.phone = $")
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
		conditions = append(conditions, builder.String())
	}
	if filter.PhoneConfirmationToken != "" {
		params = append(params, filter.PhoneConfirmationToken)
		builder.Reset()
		_, _ = builder.WriteString("a.phone_confirmation_token = $")
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
		conditions = append(conditions, builder.String())
	}
	if filter.LoginUnlockToken != "" {
		params = append(params, filter.LoginUnlockToken)
		builder.Reset()
		_, _ = builder.WriteString("a.login_unlock_token = $")
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
		conditions = append(conditions, builder.String())
	}
	if filter.ResetPasswordToken != "" {
		params = append(params, filter.ResetPasswordToken)
		builder.Reset()
		_, _ = builder.WriteString("a.reset_password_token = $")
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
		conditions = append(conditions, builder.String())
	}
	builder.Reset()
	_, _ = builder.WriteString(
		`SELECT COUNT(1)
		FROM accounts a`,
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
		`ROW_NUMBER() OVER (ORDER BY -a._id) AS row_no
		, a.id
		, a.account_type
		, a.status
		, a.name
		, a.username
		, a.confirmation_token
		, a.confirmed_at
		, a.email
		, a.unconfirmed_email
		, a.email_confirmation_token
		, a.email_confirmation_sent_at
		, a.email_confirmed_at
		, a.phone
		, a.unconfirmed_phone
		, a.phone_confirmation_token
		, a.phone_confirmation_sent_at
		, a.phone_confirmed_at
		, a.encrypted_password
		, a.last_password_change
		, a.reset_password_token
		, a.reset_password_sent_at
		, a.login_count
		, a.current_login_at
		, a.current_login_ip
		, a.last_login_at
		, a.last_login_ip
		, a.login_failed_attempts
		, a.login_unlock_token
		, a.login_locked_at
		, a.created_by
		, a.created_at
		, a.updated_at
		, a.deactivated_by
		, a.deactivated_at
		, a.deactivation_reason`,
	)
	builder.Reset()
	_, _ = builder.WriteString(query)
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
			&account.RowNo,
			&account.ID,
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

func (q *accountQuery) CreateAccount(ctx context.Context, tx pgx.Tx, request *models.NewAccount) (*accountModel.Account, error) {
	ctxt := "AccountQuery-CreateAccount"
	accountID, accountSqID, _, err := helper.GenerateUniqueID()
	if err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrGenerateUniqueID")
		return nil, err
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
	var response accountModel.Account
	if err = tx.QueryRow(
		ctx,
		`INSERT INTO accounts (
			_id
			, id
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
		accountSqID,
		request.AccountType,
		models.StatusUnconfirmed,
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
		return nil, err
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
			case "accounts_reset_password_token_key":
				err = accountModel.ErrUniqueResetPasswordTokenViolation
			case "accounts_login_unlock_token_key":
				err = accountModel.ErrUniqueLoginUnlockTokenViolation
			}
		} else {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		}
	}
	return err
}

func (q *accountQuery) FindAdmins(ctx context.Context, filter *accountModel.Filter) ([]*accountModel.Admin, int64, int64, error) {
	ctxt := "AccountQuery-FindAdmins"
	accounts, total, pages, err := q.FindAccounts(ctx, filter)
	if err != nil {
		return nil, 0, 0, err
	}
	n := len(accounts)
	response := make([]*accountModel.Admin, n)
	if n == 0 {
		return response, total, pages, nil
	}
	var builder strings.Builder
	_, _ = builder.WriteString(
		`SELECT
			account_id
			, admin_level
		FROM admins
		WHERE account_id IN (`,
	)
	params := make([]any, n)
	mapAdminOffsets := map[string]int{}
	for i, account := range accounts {
		response[i] = &accountModel.Admin{Account: account}
		params[i] = account.ID
		if i > 0 {
			_, _ = builder.WriteString(",")
		}
		_, _ = builder.WriteString("$")
		_, _ = builder.WriteString(strconv.Itoa(i + 1))
		mapAdminOffsets[account.ID] = i
	}
	_, _ = builder.WriteString(")")
	rows, err := q.dbRead.Query(ctx, builder.String(), params...)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrQuery")
		return nil, 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			accountID  string
			adminLevel uint8
		)
		if err = rows.Scan(&accountID, &adminLevel); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, 0, 0, err
		}
		if offset, ok := mapAdminOffsets[accountID]; ok {
			response[offset].AdminLevel = adminLevel
		}
	}
	return response, total, pages, nil
}

func (q *accountQuery) CreateAdmin(ctx context.Context, tx pgx.Tx, request *accountModel.NewAdmin) (*accountModel.Admin, error) {
	ctxt := "AccountQuery-CreateAdmin"
	account, err := q.CreateAccount(ctx, tx, request.NewAccount)
	if err != nil {
		return nil, err
	}
	response := accountModel.Admin{
		Account: account,
	}
	if err = tx.QueryRow(
		ctx,
		`INSERT INTO admins (
			account_id
			, admin_level
		) VALUES ($1, $2)
		RETURNING admin_level`,
		account.ID,
		request.AdminLevel,
	).Scan(&response.AdminLevel); err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		return nil, err
	}
	return &response, nil
}

func (q *accountQuery) UpdateAdmin(ctx context.Context, tx pgx.Tx, request *accountModel.Admin) error {
	ctxt := "AccountQuery-UpdateAdmin"
	err := q.UpdateAccount(ctx, tx, request.Account)
	if err != nil {
		return err
	}
	if err = tx.QueryRow(
		ctx,
		`UPDATE admins SET
			admin_level = $1
		WHERE account_id = $2
		RETURNING admin_level`,
		request.AdminLevel,
		request.ID,
	).Scan(&request.AdminLevel); err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
	}
	return err
}

func (q *accountQuery) FindUsers(ctx context.Context, filter *accountModel.Filter) ([]*accountModel.User, int64, int64, error) {
	ctxt := "AccountQuery-FindUsers"
	accounts, total, pages, err := q.FindAccounts(ctx, filter)
	if err != nil {
		return nil, 0, 0, err
	}
	n := len(accounts)
	response := make([]*accountModel.User, n)
	if n == 0 {
		return response, total, pages, nil
	}
	var builder strings.Builder
	_, _ = builder.WriteString(
		`SELECT
			account_id
			, company_id
			, user_level
			, current_session_id
		FROM users
		WHERE account_id IN (`,
	)
	params := make([]any, n)
	mapUserOffsets := map[string]int{}
	for i, account := range accounts {
		response[i] = &accountModel.User{Account: account}
		params[i] = account.ID
		if i > 0 {
			_, _ = builder.WriteString(",")
		}
		_, _ = builder.WriteString("$")
		_, _ = builder.WriteString(strconv.Itoa(i + 1))
		mapUserOffsets[account.ID] = i
	}
	_, _ = builder.WriteString(")")
	rows, err := q.dbRead.Query(ctx, builder.String(), params...)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrQuery")
		return nil, 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			accountID,
			companyID string
			userLevel        uint8
			currentSessionID *string
		)
		if err = rows.Scan(&accountID, &companyID, &userLevel, &currentSessionID); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, 0, 0, err
		}
		if offset, ok := mapUserOffsets[accountID]; ok {
			user := response[offset]
			user.CompanyID = companyID
			user.UserLevel = userLevel
			user.CurrentSessionID = currentSessionID
			response[offset] = user
		}
	}
	return response, total, pages, nil
}

func (q *accountQuery) CreateUser(ctx context.Context, tx pgx.Tx, request *accountModel.NewUser) (*accountModel.User, error) {
	ctxt := "AccountQuery-CreateUser"
	account, err := q.CreateAccount(ctx, tx, request.NewAccount)
	if err != nil {
		return nil, err
	}
	response := accountModel.User{
		Account: account,
	}
	if err = tx.QueryRow(
		ctx,
		`INSERT INTO users (
			account_id
			, company_id
			, user_level
		) VALUES ($1, $2, $3)
		RETURNING company_id
			, user_level
			, current_session_id`,
		account.ID,
		request.CompanyID,
		request.UserLevel,
	).Scan(
		&response.CompanyID,
		&response.UserLevel,
		&response.CurrentSessionID,
	); err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		return nil, err
	}
	return &response, nil
}

func (q *accountQuery) UpdateUser(ctx context.Context, tx pgx.Tx, request *accountModel.User) error {
	ctxt := "AccountQuery-UpdateUser"
	err := q.UpdateAccount(ctx, tx, request.Account)
	if err != nil {
		return err
	}
	if err = tx.QueryRow(
		ctx,
		`UPDATE users SET
			user_level = $1
			, current_session_id = $2
		WHERE account_id = $3
		RETURNING company_id
			, user_level
			, current_session_id`,
		request.UserLevel,
		request.CurrentSessionID,
		request.ID,
	).Scan(
		&request.CompanyID,
		&request.UserLevel,
		&request.CurrentSessionID,
	); err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
	}
	return err
}
