package query

import (
	"context"

	"github.com/jackc/pgx/v5"
	productCategoryModel "github.com/roysitumorang/sadia/modules/product_category/model"
)

type (
	ProductCategoryQuery interface {
		FindProductCategories(ctx context.Context, filter *productCategoryModel.Filter) ([]*productCategoryModel.ProductCategory, int64, int64, error)
		CreateProductCategory(ctx context.Context, tx pgx.Tx, request *productCategoryModel.ProductCategory) (*productCategoryModel.ProductCategory, error)
		UpdateProductCategory(ctx context.Context, tx pgx.Tx, request *productCategoryModel.ProductCategory) (*productCategoryModel.ProductCategory, error)
	}
)
