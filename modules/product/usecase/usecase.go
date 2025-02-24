package usecase

import (
	"context"

	"github.com/roysitumorang/sadia/models"
	productModel "github.com/roysitumorang/sadia/modules/product/model"
)

type (
	ProductUseCase interface {
		FindProducts(ctx context.Context, filter *productModel.Filter) ([]*productModel.Product, *models.Pagination, error)
		CreateProduct(ctx context.Context, request *productModel.Product) (*productModel.Product, error)
		UpdateProduct(ctx context.Context, request *productModel.Product) error
		ConsumeMessage(ctx context.Context) error
	}
)
