package services

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/repositories"
	"go.uber.org/zap"
)

type TransactionService interface {
	FindTransactions(ctx context.Context, filter *models.TransactionFilter) ([]*models.Transaction, *models.Pagination, error)
	CreateTransaction(ctx context.Context, tx pgx.Tx, request *models.Transaction) (*models.Transaction, error)
	ConsumeMessage(ctx context.Context, topic string, message []byte) error
}

type transactionService struct {
	transactionRepository repositories.TransactionRepository
}

func NewTransactionService(
	transactionRepository repositories.TransactionRepository,
) TransactionService {
	return &transactionService{
		transactionRepository: transactionRepository,
	}
}

func (q *transactionService) FindTransactions(ctx context.Context, filter *models.TransactionFilter) ([]*models.Transaction, *models.Pagination, error) {
	ctxt := "TransactionService-FindTransactions"
	transactionCategories, total, pages, err := q.transactionRepository.FindTransactions(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindTransactions")
		return nil, nil, err
	}
	n := len(transactionCategories)
	rows := make([]*models.Transaction, n)
	if n > 0 {
		copy(rows, transactionCategories)
	}
	pagination, err := models.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *transactionService) CreateTransaction(ctx context.Context, tx pgx.Tx, request *models.Transaction) (*models.Transaction, error) {
	ctxt := "TransactionService-CreateTransaction"
	response, err := q.transactionRepository.CreateTransaction(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateTransaction")
	}
	return response, err
}

func (q *transactionService) ConsumeMessage(ctx context.Context, topic string, message []byte) error {
	if topic != models.TopicTransaction {
		return nil
	}
	return nil
}
