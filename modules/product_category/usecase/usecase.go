package usecase

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/models"
	productCategoryModel "github.com/roysitumorang/sadia/modules/product_category/model"
)

type (
	ProductCategoryUseCase interface {
		FindProductCategories(ctx context.Context, filter *productCategoryModel.Filter) ([]*productCategoryModel.ProductCategory, *models.Pagination, error)
		CreateProductCategory(ctx context.Context, tx pgx.Tx, request *productCategoryModel.ProductCategory) (*productCategoryModel.ProductCategory, error)
		UpdateProductCategory(ctx context.Context, tx pgx.Tx, request *productCategoryModel.ProductCategory) (*productCategoryModel.ProductCategory, error)
		ConsumeMessage(ctx context.Context, topic string, message []byte) error
	}
)
