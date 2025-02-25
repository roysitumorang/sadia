package usecase

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/models"
	transactionModel "github.com/roysitumorang/sadia/modules/transaction/model"
)

type (
	TransactionUseCase interface {
		FindTransactions(ctx context.Context, filter *transactionModel.Filter) ([]*transactionModel.Transaction, *models.Pagination, error)
		CreateTransaction(ctx context.Context, tx pgx.Tx, request *transactionModel.Transaction) (*transactionModel.Transaction, error)
		ConsumeMessage(ctx context.Context) error
	}
)
