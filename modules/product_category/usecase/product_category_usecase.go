package usecase

import (
	"context"

	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	productCategoryModel "github.com/roysitumorang/sadia/modules/product_category/model"
	productCategoryQuery "github.com/roysitumorang/sadia/modules/product_category/query"
	"go.uber.org/zap"
)

type (
	productCategoryUseCase struct {
		productCategoryQuery productCategoryQuery.ProductCategoryQuery
	}
)

func New(
	productCategoryQuery productCategoryQuery.ProductCategoryQuery,
) ProductCategoryUseCase {
	return &productCategoryUseCase{
		productCategoryQuery: productCategoryQuery,
	}
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

func (q *productCategoryUseCase) ConsumeMessage(ctx context.Context, topic string, message []byte) error {
	if topic != models.TopicProductCategory {
		return nil
	}
	return nil
}
