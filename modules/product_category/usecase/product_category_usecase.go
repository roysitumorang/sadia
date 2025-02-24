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
	productCategoryModel "github.com/roysitumorang/sadia/modules/product_category/model"
	productCategoryQuery "github.com/roysitumorang/sadia/modules/product_category/query"
	serviceNsq "github.com/roysitumorang/sadia/services/nsq"
	"go.uber.org/zap"
)

type (
	productCategoryUseCase struct {
		productCategoryQuery productCategoryQuery.ProductCategoryQuery
		nsqConsumer          *serviceNsq.Consumer
	}
)

func New(
	ctx context.Context,
	productCategoryQuery productCategoryQuery.ProductCategoryQuery,
	nsqAddress string,
	nsqConfig *nsq.Config,
) (ProductCategoryUseCase, error) {
	ctxt := "ProductCategoryUseCase-New"
	nsqConsumer, err := serviceNsq.NewConsumer(ctx, nsqAddress, config.TopicProductCategory, config.NsqChannel, nsqConfig)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNewConsumer")
		return nil, err
	}
	return &productCategoryUseCase{
		productCategoryQuery: productCategoryQuery,
		nsqConsumer:          nsqConsumer,
	}, nil
}

func (q *productCategoryUseCase) FindProductCategories(ctx context.Context, filter *productCategoryModel.Filter) ([]*productCategoryModel.ProductCategory, *models.Pagination, error) {
	ctxt := "ProductCategoryUseCase-FindProductCategories"
	productCategories, total, pages, err := q.productCategoryQuery.FindProductCategories(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProductCategories")
		return nil, nil, err
	}
	n := len(productCategories)
	rows := make([]*productCategoryModel.ProductCategory, n)
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

func (q *productCategoryUseCase) CreateProductCategory(ctx context.Context, request *productCategoryModel.ProductCategory) (*productCategoryModel.ProductCategory, error) {
	ctxt := "ProductCategoryUseCase-CreateProductCategory"
	response, err := q.productCategoryQuery.CreateProductCategory(ctx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateProductCategory")
	}
	return response, err
}

func (q *productCategoryUseCase) UpdateProductCategory(ctx context.Context, request *productCategoryModel.ProductCategory) error {
	ctxt := "ProductCategoryUseCase-UpdateProductCategory"
	err := q.productCategoryQuery.UpdateProductCategory(ctx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProductCategory")
	}
	return err
}

func (q *productCategoryUseCase) ConsumeMessage(ctx context.Context) error {
	ctxt := "ProductCategoryUseCase-ConsumeMessage"
	var counter uint64
	helper.Log(ctx, zap.InfoLevel, fmt.Sprintf("consume topic %s", config.TopicProductCategory), ctxt, "")
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
