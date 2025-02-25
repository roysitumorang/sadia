package query

import (
	"context"

	"github.com/jackc/pgx/v5"
	transactionModel "github.com/roysitumorang/sadia/modules/transaction/model"
)

type (
	TransactionQuery interface {
		FindTransactions(ctx context.Context, filter *transactionModel.Filter) ([]*transactionModel.Transaction, int64, int64, error)
		CreateTransaction(ctx context.Context, tx pgx.Tx, request *transactionModel.Transaction) (*transactionModel.Transaction, error)
	}
)
