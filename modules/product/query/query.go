package query

import (
	"context"

	"github.com/jackc/pgx/v5"
	productModel "github.com/roysitumorang/sadia/modules/product/model"
)

type (
	ProductQuery interface {
		FindProducts(ctx context.Context, filter *productModel.Filter) ([]*productModel.Product, int64, int64, error)
		CreateProduct(ctx context.Context, tx pgx.Tx, request *productModel.Product) (*productModel.Product, error)
		UpdateProduct(ctx context.Context, tx pgx.Tx, request *productModel.Product) (*productModel.Product, error)
		Import(ctx context.Context, products []productModel.Product, companyID, adminID string) error
	}
)
