package usecase

import (
	"context"

	"github.com/roysitumorang/sadia/models"
	productCategoryModel "github.com/roysitumorang/sadia/modules/product_category/model"
)

type (
	ProductCategoryUseCase interface {
		FindProductCategories(ctx context.Context, filter *productCategoryModel.Filter) ([]*productCategoryModel.ProductCategory, *models.Pagination, error)
		CreateProductCategory(ctx context.Context, request *productCategoryModel.ProductCategory) (*productCategoryModel.ProductCategory, error)
		UpdateProductCategory(ctx context.Context, request *productCategoryModel.ProductCategory) error
		ConsumeMessage(ctx context.Context) error
	}
)
