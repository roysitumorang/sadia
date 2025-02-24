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
	productModel "github.com/roysitumorang/sadia/modules/product/model"
	productQuery "github.com/roysitumorang/sadia/modules/product/query"
	serviceNsq "github.com/roysitumorang/sadia/services/nsq"
	"go.uber.org/zap"
)

type (
	productUseCase struct {
		productQuery productQuery.ProductQuery
		nsqConsumer  *serviceNsq.Consumer
	}
)

func New(
	ctx context.Context,
	productQuery productQuery.ProductQuery,
	nsqAddress string,
	nsqConfig *nsq.Config,
) (ProductUseCase, error) {
	ctxt := "ProductCategoryUseCase-New"
	nsqConsumer, err := serviceNsq.NewConsumer(ctx, nsqAddress, config.TopicProductCategory, config.NsqChannel, nsqConfig)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNewConsumer")
		return nil, err
	}
	return &productUseCase{
		productQuery: productQuery,
		nsqConsumer:  nsqConsumer,
	}, nil
}

func (q *productUseCase) FindProducts(ctx context.Context, filter *productModel.Filter) ([]*productModel.Product, *models.Pagination, error) {
	ctxt := "ProductUseCase-FindProducts"
	productCategories, total, pages, err := q.productQuery.FindProducts(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
		return nil, nil, err
	}
	n := len(productCategories)
	rows := make([]*productModel.Product, n)
	if n > 0 {
		copy(rows, productCategories)
	}
	pagination, err := helper.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *productUseCase) CreateProduct(ctx context.Context, request *productModel.Product) (*productModel.Product, error) {
	ctxt := "ProductUseCase-CreateProduct"
	response, err := q.productQuery.CreateProduct(ctx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateProduct")
	}
	return response, err
}

func (q *productUseCase) UpdateProduct(ctx context.Context, request *productModel.Product) error {
	ctxt := "ProductUseCase-UpdateProduct"
	err := q.productQuery.UpdateProduct(ctx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProduct")
	}
	return err
}

func (q *productUseCase) ConsumeMessage(ctx context.Context) error {
	ctxt := "ProductUseCase-ConsumeMessage"
	var counter uint64
	helper.Log(ctx, zap.InfoLevel, fmt.Sprintf("consume topic %s", config.TopicProduct), ctxt, "")
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
