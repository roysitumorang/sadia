package usecase

import (
	"context"
	"strings"

	"github.com/gofiber/utils/v2"
	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	productModel "github.com/roysitumorang/sadia/modules/product/model"
	productQuery "github.com/roysitumorang/sadia/modules/product/query"
	"github.com/xuri/excelize/v2"
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

func (q *productUseCase) CreateProduct(ctx context.Context, tx pgx.Tx, request *productModel.Product) (*productModel.Product, error) {
	ctxt := "ProductUseCase-CreateProduct"
	response, err := q.productQuery.CreateProduct(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateProduct")
	}
	return response, err
}

func (q *productUseCase) UpdateProduct(ctx context.Context, tx pgx.Tx, request *productModel.Product) (*productModel.Product, error) {
	ctxt := "ProductUseCase-UpdateProduct"
	response, err := q.productQuery.UpdateProduct(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProduct")
	}
	return response, err
}

func (q *productUseCase) ConsumeMessage(ctx context.Context, topic string, message []byte) error {
	if topic != models.TopicProduct {
		return nil
	}
	return nil
}

func (q *productUseCase) Import(ctx context.Context, filename, companyID, adminID string) error {
	ctxt := "ProductUseCase-Import"
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
		products []productModel.Product
		product  productModel.Product
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
		sellingPrice, err := utils.ParseInt(sellingPriceRaw)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseInt")
			return err
		}
		purchasePriceRaw := row[6]
		if strings.Contains(purchasePriceRaw, ".") {
			items := strings.Split(purchasePriceRaw, ".")
			purchasePriceRaw = items[0]
		}
		purchasePrice, err := utils.ParseInt(purchasePriceRaw)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseInt")
			return err
		}
		stock, err := utils.ParseInt(row[8])
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseInt")
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
	if err = q.productQuery.Import(ctx, products, companyID, adminID); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrImport")
	}
	return err
}
