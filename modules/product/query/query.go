package query

import (
	"context"

	productModel "github.com/roysitumorang/sadia/modules/product/model"
)

type (
	ProductQuery interface {
		FindProducts(ctx context.Context, filter *productModel.Filter) ([]*productModel.Product, int64, int64, error)
		CreateProduct(ctx context.Context, request *productModel.Product) (*productModel.Product, error)
		UpdateProduct(ctx context.Context, request *productModel.Product) error
		Import(ctx context.Context, products []productModel.Product, companyID, adminID string) error
	}
)
