package migration

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
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
				, uid character varying NOT NULL UNIQUE
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
				, created_by character varying REFERENCES accounts (uid) ON UPDATE CASCADE ON DELETE SET NULL
				, created_at timestamp with time zone NOT NULL
				, updated_at timestamp with time zone NOT NULL
				, deactivated_by character varying REFERENCES accounts (uid) ON UPDATE CASCADE ON DELETE SET NULL
				, deactivated_at timestamp with time zone
				, deactivation_reason character varying
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON accounts (uid)",
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
			`CREATE TABLE json_web_tokens (
				id bigint NOT NULL PRIMARY KEY
				, uid character varying NOT NULL UNIQUE
				, token character varying NOT NULL UNIQUE
				, account_uid character varying NOT NULL REFERENCES accounts (uid) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
				, expired_at timestamp with time zone NOT NULL
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			"CREATE INDEX ON json_web_tokens (uid)",
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
			"CREATE INDEX ON json_web_tokens (account_uid)",
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
		accountID, accountUID, _, err := helper.GenerateUniqueID()
		if err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrGenerateUniqueID")
			return
		}
		confirmationToken, emailConfirmationToken, phoneConfirmationToken := helper.RandomString(32), helper.RandomString(32), helper.RandomNumber(6)
		now := time.Now()
		if _, err = tx.Exec(
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
				, created_at
				, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12)`,
			accountID,
			accountUID,
			accountModel.AccountTypeAdmin,
			accountModel.StatusUnconfirmed,
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
		}
		return
	}
}
