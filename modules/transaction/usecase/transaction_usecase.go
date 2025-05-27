package usecase

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	transactionModel "github.com/roysitumorang/sadia/modules/transaction/model"
	transactionQuery "github.com/roysitumorang/sadia/modules/transaction/query"
	"go.uber.org/zap"
)

type (
	transactionUseCase struct {
		transactionQuery transactionQuery.TransactionQuery
	}
)

func New(
	transactionQuery transactionQuery.TransactionQuery,
) TransactionUseCase {
	return &transactionUseCase{
		transactionQuery: transactionQuery,
	}
}

func (q *transactionUseCase) FindTransactions(ctx context.Context, filter *transactionModel.Filter) ([]*transactionModel.Transaction, *models.Pagination, error) {
	ctxt := "TransactionUseCase-FindTransactions"
	transactionCategories, total, pages, err := q.transactionQuery.FindTransactions(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindTransactions")
		return nil, nil, err
	}
	n := len(transactionCategories)
	rows := make([]*transactionModel.Transaction, n)
	if n > 0 {
		copy(rows, transactionCategories)
	}
	pagination, err := helper.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *transactionUseCase) CreateTransaction(ctx context.Context, tx pgx.Tx, request *transactionModel.Transaction) (*transactionModel.Transaction, error) {
	ctxt := "TransactionUseCase-CreateTransaction"
	response, err := q.transactionQuery.CreateTransaction(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateTransaction")
	}
	return response, err
}

func (q *transactionUseCase) ConsumeMessage(ctx context.Context, topic string, message []byte) error {
	if topic != models.TopicTransaction {
		return nil
	}
	return nil
}
