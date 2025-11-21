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
				id bigint NOT NULL PRIMARY KEY
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
				, created_by bigint REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE SET NULL
				, created_at timestamp with time zone NOT NULL
				, updated_at timestamp with time zone NOT NULL
				, deactivated_by bigint REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE SET NULL
				, deactivated_at timestamp with time zone
				, deactivation_reason character varying
			)`,
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
				account_id bigint NOT NULL PRIMARY KEY REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, admin_level smallint NOT NULL
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE json_web_tokens (
				id bigint NOT NULL PRIMARY KEY
				, token character varying NOT NULL UNIQUE
				, account_id bigint NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
				, expired_at timestamp with time zone NOT NULL
			)`,
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
		confirmationToken, emailConfirmationToken, phoneConfirmationToken := helper.RandomString(32), helper.RandomString(32), helper.RandomNumber(6)
		now := time.Now()
		snowflakeID := helper.GenerateSnowflakeID()
		var adminID int64
		if err = tx.QueryRow(
			ctx,
			`INSERT INTO accounts (
				id
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
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
			RETURNING id`,
			snowflakeID,
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
		).Scan(&adminID); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`INSERT INTO admins (
				account_id
				, admin_level
			) VALUES ($1, $2)`,
			adminID,
			accountModel.AdminLevelSuperAdmin,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE logs (
				id bigint NOT NULL PRIMARY KEY
				, table_name character varying NOT NULL
				, table_id character varying NOT NULL
				, activity character varying NOT NULL
				, changes jsonb NOT NULL
				, created_by bigint NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
			)`,
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
				id bigint NOT NULL PRIMARY KEY
				, name character varying NOT NULL
				, slug character varying NOT NULL UNIQUE
				, status smallint NOT NULL
				, created_by bigint NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
				, updated_by bigint NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, updated_at timestamp with time zone NOT NULL
				, deactivated_by bigint REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE SET NULL
				, deactivated_at timestamp with time zone
				, deactivation_reason character varying
			)`,
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
				account_id bigint NOT NULL PRIMARY KEY REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, company_id bigint NOT NULL REFERENCES companies (id) ON UPDATE CASCADE ON DELETE CASCADE
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
		snowflakeID = helper.GenerateSnowflakeID()
		var companyID string
		if err = tx.QueryRow(
			ctx,
			`INSERT INTO companies (
				id
				, name
				, slug
				, status
				, created_by
				, created_at
				, updated_by
				, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $5, $6)
			RETURNING id`,
			snowflakeID,
			"Apotik Lestari",
			"apotik-lestari",
			models.StatusUnconfirmed,
			adminID,
			now,
		).Scan(&companyID); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		snowflakeID = helper.GenerateSnowflakeID()
		confirmationToken, emailConfirmationToken, phoneConfirmationToken = helper.RandomString(32), helper.RandomString(32), helper.RandomNumber(6)
		var userID int64
		if err = tx.QueryRow(
			ctx,
			`INSERT INTO accounts (
				id
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
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
			RETURNING id`,
			snowflakeID,
			models.AccountTypeUser,
			models.StatusUnconfirmed,
			"Yuli Ervanita Pasaribu",
			"yuli",
			confirmationToken,
			"yuli.ervanita@gmail.com",
			emailConfirmationToken,
			"+6281376110586",
			phoneConfirmationToken,
			now,
		).Scan(&userID); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`INSERT INTO users (
				account_id
				, company_id
				, user_level
			) VALUES ($1, $2, $3)`,
			userID,
			companyID,
			accountModel.UserLevelOwner,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
		}
		return
	}
}
