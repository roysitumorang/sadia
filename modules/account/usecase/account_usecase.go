package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

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

func (q *accountUseCase) BeginTx(ctx context.Context) (pgx.Tx, error) {
	ctxt := "AccountUseCase-BeginTx"
	tx, err := q.accountQuery.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
	}
	return tx, err
}

func (q *accountUseCase) FindAccounts(ctx context.Context, filter *accountModel.Filter, urlValues url.Values) ([]*accountModel.Account, *models.Pagination, error) {
	ctxt := "AccountUseCase-FindAccounts"
	rows, total, pages, err := q.accountQuery.FindAccounts(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return nil, nil, err
	}
	pagination, err := helper.SetPagination(total, pages, filter.PerPage, filter.Page, filter.PaginationURL, urlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
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
	helper.Log(ctx, zap.InfoLevel, fmt.Sprintf("consume topic %s", config.TopicAccount), ctxt, "")
	err := q.nsqConsumer.AddHandler(ctx, func(message *nsq.Message) error {
		helper.Log(ctx, zap.InfoLevel, helper.ByteSlice2String(message.Body), ctxt, "")
		if json.Valid(message.Body) {
			var body models.Message
			err := json.Unmarshal(message.Body, &body)
			if err != nil {
				message.Requeue(-1)
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrUnmarshal")
				return err
			}
		}
		message.Finish()
		return nil
	})
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrAddHandler")
	}
	return err
}
