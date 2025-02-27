package migration

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	"go.uber.org/zap"
)

func init() {
	Migrations[1739926286270961927] = func(ctx context.Context, tx pgx.Tx) (err error) {
		ctxt := "Migration-1739926286270961927"
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE accounts (
				_id bigint NOT NULL UNIQUE
				, id character varying NOT NULL PRIMARY KEY
				, account_type smallint NOT NULL
				, status smallint NOT NULL
				, name character varying NOT NULL
				, username character varying NOT NULL UNIQUE
				, confirmation_token character varying UNIQUE
				, confirmed_at timestamp with time zone
				, email character varying UNIQUE
				, unconfirmed_email character varying
				, email_confirmation_token character varying UNIQUE
				, email_confirmation_sent_at timestamp with time zone
				, email_confirmed_at timestamp with time zone
				, phone character varying UNIQUE
				, unconfirmed_phone character varying
				, phone_confirmation_token character varying UNIQUE
				, phone_confirmation_sent_at timestamp with time zone
				, phone_confirmed_at timestamp with time zone
				, encrypted_password character varying
				, last_password_change timestamp with time zone
				, reset_password_token character varying UNIQUE
				, reset_password_sent_at timestamp with time zone
				, login_count integer NOT NULL DEFAULT 0
				, current_login_at timestamp with time zone
				, current_login_ip character varying
				, last_login_at timestamp with time zone
				, last_login_ip character varying
				, login_failed_attempts integer NOT NULL DEFAULT 0
				, login_unlock_token character varying UNIQUE
				, login_locked_at timestamp with time zone
				, created_by character varying REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE SET NULL
				, created_at timestamp with time zone NOT NULL
				, updated_at timestamp with time zone NOT NULL
				, deactivated_by character varying REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE SET NULL
				, deactivated_at timestamp with time zone
				, deactivation_reason character varying
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON accounts (_id)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON accounts (account_type)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON accounts (status)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON accounts (LOWER(name))",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON accounts (username)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON accounts (confirmation_token)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON accounts (email)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON accounts (email_confirmation_token)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON accounts (phone)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON accounts (phone_confirmation_token)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON accounts (reset_password_token)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON accounts (login_unlock_token)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON accounts (created_by)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON accounts (deactivated_by)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE admins (
				account_id character varying NOT NULL PRIMARY KEY REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, admin_level smallint NOT NULL
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE json_web_tokens (
				_id bigint NOT NULL UNIQUE
				, id character varying NOT NULL PRIMARY KEY
				, token character varying NOT NULL UNIQUE
				, account_id character varying NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
				, expired_at timestamp with time zone NOT NULL
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON json_web_tokens (_id)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON json_web_tokens (token)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON json_web_tokens (account_id)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON json_web_tokens (expired_at)",
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		accountID, accountSqID, _, err := helper.GenerateUniqueID()
		if err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrGenerateUniqueID")
			return
		}
		confirmationToken, emailConfirmationToken, phoneConfirmationToken := helper.RandomString(32), helper.RandomString(32), helper.RandomNumber(6)
		now := time.Now()
		if _, err = tx.Exec(
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
				, created_at
				, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12)`,
			accountID,
			accountSqID,
			models.AccountTypeAdmin,
			models.StatusUnconfirmed,
			"Roy Situmorang",
			"roy",
			confirmationToken,
			"roy.situmorang@gmail.com",
			emailConfirmationToken,
			"+6285233494271",
			phoneConfirmationToken,
			now,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`INSERT INTO admins (
				account_id
				, admin_level
			) VALUES ($1, $2)`,
			accountSqID,
			accountModel.AdminLevelSuperAdmin,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE logs (
				_id bigint NOT NULL UNIQUE
				, id character varying NOT NULL PRIMARY KEY
				, table_name character varying NOT NULL
				, table_id character varying NOT NULL
				, activity character varying NOT NULL
				, changes jsonb NOT NULL
				, created_by character varying NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON logs (_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON logs (table_name)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON logs (table_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON logs (created_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE companies (
				_id bigint NOT NULL UNIQUE
				, id character varying NOT NULL PRIMARY KEY
				, name character varying NOT NULL
				, slug character varying NOT NULL UNIQUE
				, status smallint NOT NULL
				, created_by character varying NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
				, updated_by character varying NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, updated_at timestamp with time zone NOT NULL
				, deactivated_by character varying REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE SET NULL
				, deactivated_at timestamp with time zone
				, deactivation_reason character varying
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON companies (_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON companies (LOWER(name))`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON companies (slug)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON companies (status)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON companies (created_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON companies (updated_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON companies (deactivated_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE users (
				account_id character varying NOT NULL PRIMARY KEY REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, company_id character varying NOT NULL REFERENCES companies (id) ON UPDATE CASCADE ON DELETE CASCADE
				, user_level smallint NOT NULL
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON users (company_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE stores (
				_id bigint NOT NULL UNIQUE
				, id character varying NOT NULL PRIMARY KEY
				, company_id character varying NOT NULL REFERENCES companies (id) ON UPDATE CASCADE ON DELETE CASCADE
				, name character varying NOT NULL
				, slug character varying NOT NULL
				, created_by character varying NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
				, updated_by character varying NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, updated_at timestamp with time zone NOT NULL
			);`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON stores (_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON stores (company_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE UNIQUE INDEX ON stores (LOWER(name), company_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE UNIQUE INDEX ON stores (slug, company_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON stores (created_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON stores (updated_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE sessions (
				_id bigint NOT NULL UNIQUE
				, id character varying NOT NULL PRIMARY KEY
				, store_id character varying NOT NULL REFERENCES stores (id) ON UPDATE CASCADE ON DELETE CASCADE
				, date date NOT NULL
				, status smallint NOT NULL
				, cashbox_value integer NOT NULL
				, cashbox_note character varying NOT NULL
				, transaction_value bigint NOT NULL DEFAULT 0
				, take_money_value bigint NOT NULL DEFAULT 0
				, created_by character varying NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
				, closed_at timestamp with time zone
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON sessions (_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON sessions (store_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE UNIQUE INDEX ON sessions (date, created_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON sessions (status)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON sessions (created_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`ALTER TABLE users
				ADD COLUMN current_session_id character varying REFERENCES sessions (id) ON UPDATE CASCADE ON DELETE CASCADE`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON users (current_session_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`ALTER TABLE stores
				ADD COLUMN current_session_id character varying REFERENCES sessions (id) ON UPDATE CASCADE ON DELETE CASCADE`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON stores (current_session_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE session_take_money_line_items (
				_id bigint NOT NULL UNIQUE
				, id character varying NOT NULL PRIMARY KEY
				, session_id character varying NOT NULL REFERENCES sessions (id) ON UPDATE CASCADE ON DELETE CASCADE
				, description character varying NOT NULL
				, value bigint NOT NULL
				, created_by character varying NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON session_take_money_line_items (_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON session_take_money_line_items (session_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON session_take_money_line_items (created_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE product_categories (
				_id bigint NOT NULL UNIQUE
				, id character varying NOT NULL PRIMARY KEY
				, company_id character varying NOT NULL REFERENCES companies (id) ON UPDATE CASCADE ON DELETE CASCADE
				, name character varying NOT NULL
				, slug character varying NOT NULL
				, created_by character varying NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
				, updated_by character varying NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, updated_at timestamp with time zone NOT NULL
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON product_categories (_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON product_categories (company_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE UNIQUE INDEX ON product_categories (LOWER(name), company_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE UNIQUE INDEX ON product_categories (slug, company_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON product_categories (created_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON product_categories (updated_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE products (
				_id bigint NOT NULL UNIQUE
				, id character varying NOT NULL PRIMARY KEY
				, company_id character varying NOT NULL REFERENCES companies (id) ON UPDATE CASCADE ON DELETE CASCADE
				, category_id character varying REFERENCES product_categories (id) ON UPDATE CASCADE ON DELETE SET NULL
				, name character varying NOT NULL
				, slug character varying NOT NULL
				, uom character varying NOT NULL
				, stock bigint NOT NULL
				, price bigint NOT NULL
				, created_by character varying NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
				, updated_by character varying NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, updated_at timestamp with time zone NOT NULL
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON products (_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON products (company_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON products (category_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE UNIQUE INDEX ON products (LOWER(name), company_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE UNIQUE INDEX ON products (slug, company_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON products (stock)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON products (price)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON products (created_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON products (updated_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE transactions (
				_id bigint NOT NULL UNIQUE
				, id character varying NOT NULL PRIMARY KEY
				, session_id character varying NOT NULL REFERENCES sessions (id) ON UPDATE CASCADE ON DELETE CASCADE
				, reference_no character varying NOT NULL UNIQUE
				, subtotal bigint NOT NULL
				, discount bigint NOT NULL
				, tax_rate float8 NOT NULL
				, tax bigint NOT NULL
				, total bigint NOT NULL
				, payment_method smallint NOT NULL
				, created_by character varying NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON transactions (_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON transactions (session_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON transactions (reference_no)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON transactions (created_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON transactions (created_at)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE transaction_line_items (
				_id bigint NOT NULL UNIQUE
				, id character varying NOT NULL PRIMARY KEY
				, transaction_id character varying NOT NULL REFERENCES transactions (id) ON UPDATE CASCADE ON DELETE CASCADE
				, product_id character varying NOT NULL REFERENCES products (id) ON UPDATE CASCADE ON DELETE CASCADE
				, product_name character varying NOT NULL
				, product_uom character varying NOT NULL
				, quantity bigint NOT NULL
				, price bigint NOT NULL
				, subtotal bigint NOT NULL
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON transaction_line_items (_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON transaction_line_items (transaction_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON transaction_line_items (product_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE sequences (
				_id bigint NOT NULL UNIQUE
				, id character varying NOT NULL PRIMARY KEY
				, name character varying NOT NULL UNIQUE
				, number integer NOT NULL
				, created_by character varying NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
				, updated_by character varying NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, updated_at timestamp with time zone NOT NULL
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON sequences (_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON sequences (name)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON sequences (created_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON sequences (updated_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
		}
		return
	}
}
