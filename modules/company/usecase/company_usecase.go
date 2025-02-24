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
	companyModel "github.com/roysitumorang/sadia/modules/company/model"
	companyQuery "github.com/roysitumorang/sadia/modules/company/query"
	serviceNsq "github.com/roysitumorang/sadia/services/nsq"
	"go.uber.org/zap"
)

type (
	companyUseCase struct {
		companyQuery companyQuery.CompanyQuery
		nsqConsumer  *serviceNsq.Consumer
	}
)

func New(
	ctx context.Context,
	companyQuery companyQuery.CompanyQuery,
	nsqAddress string,
	nsqConfig *nsq.Config,
) (CompanyUseCase, error) {
	ctxt := "companyUseCase-New"
	nsqConsumer, err := serviceNsq.NewConsumer(ctx, nsqAddress, config.TopicCompany, config.NsqChannel, nsqConfig)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNewConsumer")
		return nil, err
	}
	return &companyUseCase{
		companyQuery: companyQuery,
		nsqConsumer:  nsqConsumer,
	}, nil
}

func (q *companyUseCase) FindCompanies(ctx context.Context, filter *companyModel.Filter) ([]*companyModel.Company, *models.Pagination, error) {
	ctxt := "CompanyUseCase-FindCompanies"
	companies, total, pages, err := q.companyQuery.FindCompanies(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindCompanies")
		return nil, nil, err
	}
	n := len(companies)
	rows := make([]*companyModel.Company, n)
	if n > 0 {
		copy(rows, companies)
	}
	pagination, err := helper.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *companyUseCase) CreateCompany(ctx context.Context, tx pgx.Tx, request *companyModel.NewCompany) (*companyModel.Company, error) {
	ctxt := "CompanyUseCase-CreateCompany"
	response, err := q.companyQuery.CreateCompany(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateCompany")
	}
	return response, err
}

func (q *companyUseCase) UpdateCompany(ctx context.Context, tx pgx.Tx, request *companyModel.Company) error {
	ctxt := "CompanyUseCase-UpdateCompany"
	err := q.companyQuery.UpdateCompany(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
	}
	return err
}

func (q *companyUseCase) ConsumeMessage(ctx context.Context) error {
	ctxt := "CompanyUseCase-ConsumeMessage"
	var counter uint64
	helper.Log(ctx, zap.InfoLevel, fmt.Sprintf("consume topic %s", config.TopicCompany), ctxt, "")
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
