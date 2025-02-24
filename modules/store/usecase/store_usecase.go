package usecase

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/goccy/go-json"
	"github.com/nsqio/go-nsq"
	"github.com/roysitumorang/sadia/config"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	storeModel "github.com/roysitumorang/sadia/modules/store/model"
	storeQuery "github.com/roysitumorang/sadia/modules/store/query"
	serviceNsq "github.com/roysitumorang/sadia/services/nsq"
	"go.uber.org/zap"
)

type (
	storeUseCase struct {
		storeQuery  storeQuery.StoreQuery
		nsqConsumer *serviceNsq.Consumer
	}
)

func New(
	ctx context.Context,
	storeQuery storeQuery.StoreQuery,
	nsqAddress string,
	nsqConfig *nsq.Config,
) (StoreUseCase, error) {
	ctxt := "StoreCategoryUseCase-New"
	nsqConsumer, err := serviceNsq.NewConsumer(ctx, nsqAddress, config.TopicStore, config.NsqChannel, nsqConfig)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNewConsumer")
		return nil, err
	}
	return &storeUseCase{
		storeQuery:  storeQuery,
		nsqConsumer: nsqConsumer,
	}, nil
}

func (q *storeUseCase) FindStores(ctx context.Context, filter *storeModel.Filter) ([]*storeModel.Store, *models.Pagination, error) {
	ctxt := "StoreUseCase-FindStores"
	storeCategories, total, pages, err := q.storeQuery.FindStores(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindStores")
		return nil, nil, err
	}
	n := len(storeCategories)
	rows := make([]*storeModel.Store, n)
	if n > 0 {
		copy(rows, storeCategories)
	}
	pagination, err := helper.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *storeUseCase) CreateStore(ctx context.Context, request *storeModel.Store) (*storeModel.Store, error) {
	ctxt := "StoreUseCase-CreateStore"
	response, err := q.storeQuery.CreateStore(ctx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateStore")
	}
	return response, err
}

func (q *storeUseCase) UpdateStore(ctx context.Context, request *storeModel.Store) error {
	ctxt := "StoreUseCase-UpdateStore"
	err := q.storeQuery.UpdateStore(ctx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateStore")
	}
	return err
}

func (q *storeUseCase) ConsumeMessage(ctx context.Context) error {
	ctxt := "StoreUseCase-ConsumeMessage"
	var counter uint64
	helper.Log(ctx, zap.InfoLevel, fmt.Sprintf("consume topic %s", config.TopicStore), ctxt, "")
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
