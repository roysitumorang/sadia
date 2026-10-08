package services

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/repositories"
	"go.uber.org/zap"
)

type ProductCategoryService interface {
	FindProductCategories(ctx context.Context, filter *models.ProductCategoryFilter) ([]*models.ProductCategory, *models.Pagination, error)
	CreateProductCategory(ctx context.Context, tx pgx.Tx, request *models.ProductCategory) (*models.ProductCategory, error)
	UpdateProductCategory(ctx context.Context, tx pgx.Tx, request *models.ProductCategory) (*models.ProductCategory, error)
	ConsumeMessage(ctx context.Context, topic string, message []byte) error
}

type productCategoryService struct {
	productCategoryRepository repositories.ProductCategoryRepository
}

func NewProductCategoryService(
	productCategoryRepository repositories.ProductCategoryRepository,
) ProductCategoryService {
	return &productCategoryService{
		productCategoryRepository: productCategoryRepository,
	}
}

func (q *productCategoryService) FindProductCategories(ctx context.Context, filter *models.ProductCategoryFilter) ([]*models.ProductCategory, *models.Pagination, error) {
	ctxt := "ProductCategoryService-FindProductCategories"
	productCategories, total, pages, err := q.productCategoryRepository.FindProductCategories(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProductCategories")
		return nil, nil, err
	}
	n := len(productCategories)
	rows := make([]*models.ProductCategory, n)
	if n > 0 {
		copy(rows, productCategories)
	}
	pagination, err := models.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *productCategoryService) CreateProductCategory(ctx context.Context, tx pgx.Tx, request *models.ProductCategory) (*models.ProductCategory, error) {
	ctxt := "ProductCategoryService-CreateProductCategory"
	response, err := q.productCategoryRepository.CreateProductCategory(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateProductCategory")
	}
	return response, err
}

func (q *productCategoryService) UpdateProductCategory(ctx context.Context, tx pgx.Tx, request *models.ProductCategory) (*models.ProductCategory, error) {
	ctxt := "ProductCategoryService-UpdateProductCategory"
	response, err := q.productCategoryRepository.UpdateProductCategory(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProductCategory")
	}
	return response, err
}

func (q *productCategoryService) ConsumeMessage(ctx context.Context, topic string, message []byte) error {
	if topic != models.TopicProductCategory {
		return nil
	}
	return nil
}
