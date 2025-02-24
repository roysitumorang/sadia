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

func (q *accountUseCase) FindAccounts(ctx context.Context, filter *accountModel.Filter) ([]*accountModel.Account, *models.Pagination, error) {
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
	pagination, err := helper.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *accountUseCase) CreateAccount(ctx context.Context, tx pgx.Tx, request *accountModel.NewAccount) (*accountModel.Account, error) {
	ctxt := "AccountUseCase-CreateAccount"
	response, err := q.accountQuery.CreateAccount(ctx, tx, request)
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

func (q *accountUseCase) FindAdmins(ctx context.Context, filter *accountModel.Filter) ([]*accountModel.Admin, *models.Pagination, error) {
	ctxt := "AccountUseCase-FindAdmins"
	filter.AccountTypes = []uint8{accountModel.AccountTypeAdmin}
	admins, total, pages, err := q.accountQuery.FindAdmins(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return nil, nil, err
	}
	n := len(admins)
	rows := make([]*accountModel.Admin, n)
	if n > 0 {
		copy(rows, admins)
	}
	pagination, err := helper.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *accountUseCase) CreateAdmin(ctx context.Context, tx pgx.Tx, request *accountModel.NewAdmin) (*accountModel.Admin, error) {
	ctxt := "AccountUseCase-CreateAdmin"
	request.AccountType = accountModel.AccountTypeAdmin
	response, err := q.accountQuery.CreateAdmin(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateAdmin")
	}
	return response, err
}

func (q *accountUseCase) UpdateAdmin(ctx context.Context, tx pgx.Tx, request *accountModel.Admin) error {
	ctxt := "AccountUseCase-UpdateAdmin"
	err := q.accountQuery.UpdateAdmin(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
	}
	return err
}

func (q *accountUseCase) FindUsers(ctx context.Context, filter *accountModel.Filter) ([]*accountModel.User, *models.Pagination, error) {
	ctxt := "AccountUseCase-FindUsers"
	filter.AccountTypes = []uint8{accountModel.AccountTypeUser}
	users, total, pages, err := q.accountQuery.FindUsers(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return nil, nil, err
	}
	n := len(users)
	rows := make([]*accountModel.User, n)
	if n > 0 {
		copy(rows, users)
	}
	pagination, err := helper.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *accountUseCase) CreateUser(ctx context.Context, tx pgx.Tx, request *accountModel.NewUser) (*accountModel.User, error) {
	ctxt := "AccountUseCase-CreateUser"
	request.AccountType = accountModel.AccountTypeUser
	response, err := q.accountQuery.CreateUser(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateUser")
	}
	return response, err
}

func (q *accountUseCase) UpdateUser(ctx context.Context, tx pgx.Tx, request *accountModel.User) error {
	ctxt := "AccountUseCase-UpdateUser"
	err := q.accountQuery.UpdateUser(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
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
