package migration

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"go.uber.org/zap"
)

func init() {
	Migrations[1748334365969169046] = func(ctx context.Context, tx pgx.Tx) (err error) {
		ctxt := "Migration-1748334365969169046"
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE sessions (
				id uint8 NOT NULL PRIMARY KEY
				, company_id uint8 NOT NULL REFERENCES companies (id) ON UPDATE CASCADE ON DELETE CASCADE
				, date date NOT NULL
				, status uint1 NOT NULL
				, cashbox_value integer NOT NULL
				, cashbox_note character varying NOT NULL
				, transaction_value uint8 NOT NULL DEFAULT 0
				, spending_value uint8 NOT NULL DEFAULT 0
				, created_by uint8 NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
				, closed_by uint8 REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE SET NULL
				, closed_at timestamp with time zone
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON sessions (company_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE UNIQUE INDEX ON sessions (date, company_id)`,
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
			`CREATE INDEX ON sessions (closed_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`ALTER TABLE companies
				ADD COLUMN session_id uint8 REFERENCES sessions (id) ON UPDATE CASCADE ON DELETE SET NULL`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON companies (session_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE spendings (
				id uint8 NOT NULL PRIMARY KEY
				, session_id uint8 NOT NULL REFERENCES sessions (id) ON UPDATE CASCADE ON DELETE CASCADE
				, description character varying NOT NULL
				, value uint8 NOT NULL
				, created_by uint8 NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
			)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON spendings (session_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON spendings (created_by)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE TABLE product_categories (
				id uint8 NOT NULL PRIMARY KEY
				, company_id uint8 NOT NULL REFERENCES companies (id) ON UPDATE CASCADE ON DELETE CASCADE
				, name character varying NOT NULL
				, slug character varying NOT NULL
				, created_by uint8 NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
				, updated_by uint8 NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, updated_at timestamp with time zone NOT NULL
			)`,
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
				id uint8 NOT NULL PRIMARY KEY
				, company_id uint8 NOT NULL REFERENCES companies (id) ON UPDATE CASCADE ON DELETE CASCADE
				, category_id uint8 REFERENCES product_categories (id) ON UPDATE CASCADE ON DELETE SET NULL
				, name character varying NOT NULL
				, code character varying NOT NULL
				, uom character varying NOT NULL
				, minimum_stock uint8 NOT NULL
				, stock uint8 NOT NULL
				, base_price uint8 NOT NULL
				, selling_price uint8 NOT NULL
				, weight uint8 NOT NULL
				, rack_position character varying NOT NULL
				, created_by uint8 NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
				, updated_by uint8 NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, updated_at timestamp with time zone NOT NULL
			)`,
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
			`CREATE UNIQUE INDEX ON products (LOWER(name), LOWER(code), LOWER(uom), company_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON products (LOWER(name))`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON products (LOWER(code))`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON products (LOWER(uom))`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON products (minimum_stock)`,
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
			`CREATE INDEX ON products (base_price)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON products (selling_price)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON products (rack_position)`,
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
				id uint8 NOT NULL PRIMARY KEY
				, session_id uint8 NOT NULL REFERENCES sessions (id) ON UPDATE CASCADE ON DELETE CASCADE
				, reference_no character varying NOT NULL UNIQUE
				, subtotal uint8 NOT NULL
				, discount uint8 NOT NULL
				, total uint8 NOT NULL
				, payment_method uint1 NOT NULL
				, created_by uint8 NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
			)`,
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
				id uint8 NOT NULL PRIMARY KEY
				, transaction_id uint8 NOT NULL REFERENCES transactions (id) ON UPDATE CASCADE ON DELETE CASCADE
				, product_id uint8 NOT NULL REFERENCES products (id) ON UPDATE CASCADE ON DELETE CASCADE
				, product_name character varying NOT NULL
				, product_code character varying NOT NULL
				, product_uom character varying NOT NULL
				, stock uint8 NOT NULL
				, base_price uint8 NOT NULL
				, selling_price uint8 NOT NULL
				, weight uint8 NOT NULL
				, quantity uint8 NOT NULL
				, subtotal uint8 NOT NULL
			)`,
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
				id uint8 NOT NULL PRIMARY KEY
				, name character varying NOT NULL UNIQUE
				, number integer NOT NULL
				, created_by uint8 NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, created_at timestamp with time zone NOT NULL
				, updated_by uint8 NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE CASCADE
				, updated_at timestamp with time zone NOT NULL
			)`,
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
