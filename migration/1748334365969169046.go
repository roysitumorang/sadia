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
				, code character varying NOT NULL
				, uom character varying NOT NULL
				, stock_type smallint NOT NULL
				, minimum_stock bigint NOT NULL
				, stock bigint NOT NULL
				, purchase_price bigint NOT NULL
				, selling_price bigint NOT NULL
				, weight bigint NOT NULL
				, discount_type smallint NOT NULL
				, discount_value bigint NOT NULL
				, rack_position character varying NOT NULL
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
			`CREATE INDEX ON products (LOWER(name), company_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON products (code, company_id)`,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return
		}
		if _, err = tx.Exec(
			ctx,
			`CREATE INDEX ON products (stock_type)`,
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
			`CREATE INDEX ON products (purchase_price)`,
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
