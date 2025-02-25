package usecase

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/goccy/go-json"
	"github.com/jackc/pgx/v5"
	"github.com/nsqio/go-nsq"
	"github.com/roysitumorang/sadia/config"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	transactionModel "github.com/roysitumorang/sadia/modules/transaction/model"
	transactionQuery "github.com/roysitumorang/sadia/modules/transaction/query"
	serviceNsq "github.com/roysitumorang/sadia/services/nsq"
	"go.uber.org/zap"
)

type (
	transactionUseCase struct {
		transactionQuery transactionQuery.TransactionQuery
		nsqConsumer      *serviceNsq.Consumer
	}
)

func New(
	ctx context.Context,
	transactionQuery transactionQuery.TransactionQuery,
	nsqAddress string,
	nsqConfig *nsq.Config,
) (TransactionUseCase, error) {
	ctxt := "TransactionCategoryUseCase-New"
	nsqConsumer, err := serviceNsq.NewConsumer(ctx, nsqAddress, config.TopicTransaction, config.NsqChannel, nsqConfig)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNewConsumer")
		return nil, err
	}
	return &transactionUseCase{
		transactionQuery: transactionQuery,
		nsqConsumer:      nsqConsumer,
	}, nil
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

func (q *transactionUseCase) ConsumeMessage(ctx context.Context) error {
	ctxt := "TransactionUseCase-ConsumeMessage"
	var counter uint64
	helper.Log(ctx, zap.InfoLevel, fmt.Sprintf("consume topic %s", config.TopicTransaction), ctxt, "")
	err := q.nsqConsumer.AddHandler(ctx, func(message *nsq.Message) error {
		now := time.Now()
		atomic.AddUint64(&counter, 1)
		var body models.Message
		if err := json.Unmarshal(message.Body, &body); err != nil {
			message.Finish()
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrUnmarshal")
			return nil
		}
		message.Finish()
		duration := time.Since(now)
		helper.Log(
			ctx,
			zap.InfoLevel,
			fmt.Sprintf(
				"message on topic %s@%d: %s, consumed in %s",
				config.TopicTransaction,
				atomic.LoadUint64(&counter),
				helper.ByteSlice2String(message.Body),
				duration.String(),
			),
			ctxt,
			"",
		)
		return nil
	})
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrAddHandler")
	}
	return err
}
