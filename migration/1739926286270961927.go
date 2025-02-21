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
				, email character varying UNIQUE
				, unconfirmed_email character varying
				, email_confirmation_token character varying UNIQUE
				, email_confirmed_at timestamp with time zone
				, phone character varying UNIQUE
				, unconfirmed_phone character varying
				, phone_confirmation_token character varying UNIQUE
				, phone_confirmed_at timestamp with time zone
				, encrypted_password character varying
				, last_password_change timestamp with time zone
				, reset_password_token character varying UNIQUE
				, login_count integer NOT NULL DEFAULT 0
				, current_login_at timestamp with time zone
				, current_login_ip character varying
				, last_login_at timestamp with time zone
				, last_login_ip character varying
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
		now := time.Now()
		encryptedPassword, err := helper.HashPassword("s@dia1d")
		if err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrHashPassword")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`INSERT INTO accounts (
				id
				, uid
				, account_type
				, status
				, name
				, username
				, email
				, email_confirmed_at
				, phone
				, phone_confirmed_at
				, encrypted_password
				, last_password_change
				, created_at
				, updated_at
			) VALUES (
				$1
				, $2
				, $3
				, $4
				, $5
				, $6
				, $7
				, $10
				, $8
				, $10
				, $9
				, $10
				, $10
				, $10
			)`,
			accountID,
			accountUID,
			accountModel.AccountTypeAdmin,
			accountModel.StatusActive,
			"Roy Situmorang",
			"roy",
			"roy.situmorang@gmail.com",
			"+6285233494271",
			encryptedPassword,
			now,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		return
	}
}
