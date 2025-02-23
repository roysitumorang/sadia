package usecase

import (
	"context"
	"fmt"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/goccy/go-json"
	"github.com/jackc/pgx/v5"
	"github.com/nsqio/go-nsq"
	"github.com/roysitumorang/sadia/config"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountQuery "github.com/roysitumorang/sadia/modules/account/query"
	serviceNsq "github.com/roysitumorang/sadia/services/nsq"
	"go.uber.org/zap"
)

type (
	accountUseCase struct {
		accountQuery accountQuery.AccountQuery
		nsqConsumer  *serviceNsq.Consumer
	}
)

func New(
	ctx context.Context,
	accountQuery accountQuery.AccountQuery,
	nsqAddress string,
	nsqConfig *nsq.Config,
) (AccountUseCase, error) {
	ctxt := "AccountUseCase-New"
	nsqConsumer, err := serviceNsq.NewConsumer(ctx, nsqAddress, config.TopicAccount, config.NsqChannel, nsqConfig)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNewConsumer")
		return nil, err
	}
	return &accountUseCase{
		accountQuery: accountQuery,
		nsqConsumer:  nsqConsumer,
	}, nil
}

func (q *accountUseCase) FindAccounts(ctx context.Context, filter *accountModel.Filter, urlValues url.Values) ([]*accountModel.Account, *models.Pagination, error) {
	ctxt := "AccountUseCase-FindAccounts"
	accounts, total, pages, err := q.accountQuery.FindAccounts(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return nil, nil, err
	}
	n := len(accounts)
	rows := make([]*accountModel.Account, n)
	if n > 0 {
		copy(rows, accounts)
	}
	pagination, err := helper.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, urlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *accountUseCase) CreateAccount(ctx context.Context, request *accountModel.NewAccount) (*accountModel.Account, error) {
	ctxt := "AccountUseCase-CreateAccount"
	response, err := q.accountQuery.CreateAccount(ctx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateAccount")
	}
	return response, err
}

func (q *accountUseCase) UpdateAccount(ctx context.Context, tx pgx.Tx, request *accountModel.Account) error {
	ctxt := "AccountUseCase-UpdateAccount"
	err := q.accountQuery.UpdateAccount(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
	}
	return err
}

func (q *accountUseCase) ConsumeMessage(ctx context.Context) error {
	ctxt := "AccountUseCase-ConsumeMessage"
	var counter uint64
	helper.Log(ctx, zap.InfoLevel, fmt.Sprintf("consume topic %s", config.TopicAccount), ctxt, "")
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
				config.TopicAccount,
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
