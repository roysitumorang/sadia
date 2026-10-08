package repositories

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/roysitumorang/sadia/helper"
	"go.uber.org/zap"
)

var dbWrite *pgxpool.Pool

func SetDbWrite(db *pgxpool.Pool) {
	dbWrite = db
}

func BeginTx(ctx context.Context) (pgx.Tx, error) {
	ctxt := "Repositories-BeginTx"
	tx, err := dbWrite.Begin(ctx)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrBegin")
	}
	return tx, err
}
