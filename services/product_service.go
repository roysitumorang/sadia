package services

import (
	"context"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/repositories"
	"github.com/xuri/excelize/v2"
	"go.uber.org/zap"
)

type ProductService interface {
	FindProducts(ctx context.Context, filter *models.ProductFilter) ([]*models.Product, *models.Pagination, error)
	CreateProduct(ctx context.Context, tx pgx.Tx, request *models.Product) (*models.Product, error)
	UpdateProduct(ctx context.Context, tx pgx.Tx, request *models.Product) (*models.Product, error)
	ConsumeMessage(ctx context.Context, topic string, message []byte) error
	Import(ctx context.Context, filename string, companyID, adminID uint64) error
}

type productService struct {
	productRepository repositories.ProductRepository
}

func NewProductService(
	productRepository repositories.ProductRepository,
) ProductService {
	return &productService{
		productRepository: productRepository,
	}
}

func (q *productService) FindProducts(ctx context.Context, filter *models.ProductFilter) ([]*models.Product, *models.Pagination, error) {
	ctxt := "ProductService-FindProducts"
	productCategories, total, pages, err := q.productRepository.FindProducts(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
		return nil, nil, err
	}
	n := len(productCategories)
	rows := make([]*models.Product, n)
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

func (q *productService) CreateProduct(ctx context.Context, tx pgx.Tx, request *models.Product) (*models.Product, error) {
	ctxt := "ProductService-CreateProduct"
	response, err := q.productRepository.CreateProduct(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateProduct")
	}
	return response, err
}

func (q *productService) UpdateProduct(ctx context.Context, tx pgx.Tx, request *models.Product) (*models.Product, error) {
	ctxt := "ProductService-UpdateProduct"
	response, err := q.productRepository.UpdateProduct(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProduct")
	}
	return response, err
}

func (q *productService) ConsumeMessage(ctx context.Context, topic string, message []byte) error {
	if topic != models.TopicProduct {
		return nil
	}
	return nil
}

func (q *productService) Import(ctx context.Context, filename string, companyID, adminID uint64) error {
	ctxt := "ProductService-Import"
	f, err := excelize.OpenFile(filename)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrOpenFile")
		return err
	}
	defer func() {
		if err = f.Close(); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrClose")
		}
	}()
	rows, err := f.GetRows("barang")
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGetRows")
		return err
	}
	var (
		products []models.Product
		product  models.Product
	)
	for i, row := range rows {
		if i < 2 {
			continue
		}
		sellingPriceRaw := row[5]
		if strings.Contains(sellingPriceRaw, ".") {
			items := strings.Split(sellingPriceRaw, ".")
			sellingPriceRaw = items[0]
		}
		sellingPrice, err := strconv.ParseUint(sellingPriceRaw, 10, 64)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
			return err
		}
		purchasePriceRaw := row[6]
		if strings.Contains(purchasePriceRaw, ".") {
			items := strings.Split(purchasePriceRaw, ".")
			purchasePriceRaw = items[0]
		}
		purchasePrice, err := strconv.ParseUint(purchasePriceRaw, 10, 64)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
			return err
		}
		stock, err := strconv.ParseUint(row[8], 10, 64)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
			return err
		}
		product.Code = row[1]
		product.Name = row[2]
		product.SellingPrice = sellingPrice
		product.BasePrice = purchasePrice
		product.Stock = stock
		product.UOM = row[11]
		product.RackPosition = row[13]
		products = append(products, product)
	}
	if err = q.productRepository.Import(ctx, products, companyID, adminID); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrImport")
	}
	return err
}
