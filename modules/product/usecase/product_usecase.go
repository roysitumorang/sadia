package usecase

import (
	"context"

	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	productModel "github.com/roysitumorang/sadia/modules/product/model"
	productQuery "github.com/roysitumorang/sadia/modules/product/query"
	"go.uber.org/zap"
)

type (
	productUseCase struct {
		productQuery productQuery.ProductQuery
	}
)

func New(
	productQuery productQuery.ProductQuery,
) ProductUseCase {
	return &productUseCase{
		productQuery: productQuery,
	}
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

func (q *productUseCase) ConsumeMessage(ctx context.Context, topic string, message []byte) error {
	if topic != models.TopicProduct {
		return nil
	}
	return nil
}
