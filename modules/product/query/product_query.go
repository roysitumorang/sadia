package query

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/govalues/decimal"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/roysitumorang/sadia/helper"
	productModel "github.com/roysitumorang/sadia/modules/product/model"
	"go.uber.org/zap"
)

type (
	productQuery struct {
		dbRead,
		dbWrite *pgxpool.Pool
	}
)

func New(
	dbRead,
	dbWrite *pgxpool.Pool,
) ProductQuery {
	return &productQuery{
		dbRead:  dbRead,
		dbWrite: dbWrite,
	}
}

func (q *productQuery) FindProducts(ctx context.Context, filter *productModel.Filter) ([]*productModel.Product, int64, int64, error) {
	ctxt := "ProductQuery-FindProducts"
	var (
		params     []any
		conditions []string
		builder    strings.Builder
	)
	if len(filter.ProductIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("p.id IN (")
		for i, productID := range filter.ProductIDs {
			params = append(params, productID)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	if len(filter.ProductCategoryIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("p.product_category_id IN (")
		for i, productCategoryID := range filter.ProductCategoryIDs {
			params = append(params, productCategoryID)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	if len(filter.CompanyIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("p.company_id IN (")
		for i, companyID := range filter.CompanyIDs {
			params = append(params, companyID)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	if filter.Keyword != "" {
		builder.Reset()
		_, _ = builder.WriteString("%%")
		_, _ = builder.WriteString(strings.ToLower(filter.Keyword))
		_, _ = builder.WriteString("%%")
		params = append(params, builder.String())
		n := strconv.Itoa(len(params))
		builder.Reset()
		_, _ = builder.WriteString("(LOWER(p.name) LIKE $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR p.slug LIKE $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	builder.Reset()
	_, _ = builder.WriteString(
		`SELECT COUNT(1)
		FROM products p`,
	)
	if len(conditions) > 0 {
		_, _ = builder.WriteString(" WHERE")
		for i, condition := range conditions {
			if i > 0 {
				_, _ = builder.WriteString(" AND")
			}
			_, _ = builder.WriteString(" ")
			_, _ = builder.WriteString(condition)
		}
	}
	query := builder.String()
	var total int64
	err := q.dbRead.QueryRow(ctx, query, params...).Scan(&total)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
		return nil, 0, 0, err
	}
	if total == 0 {
		return nil, 0, 0, nil
	}
	query = strings.ReplaceAll(
		query,
		"COUNT(1)",
		`ROW_NUMBER() OVER (ORDER BY -p._id) AS row_no
		, p.id
		, p.company_id
		, p.category_id
		, p.name
		, p.slug
		, p.uom
		, p.stock
		, p.price
		, p.created_by
		, p.created_at
		, p.updated_by
		, p.updated_at`,
	)
	builder.Reset()
	_, _ = builder.WriteString(query)
	pages := int64(1)
	if filter.Limit > 0 {
		totalDecimal, err := decimal.New(total, 0)
		if err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrNew")
			return nil, 0, 0, err
		}
		perPageDecimal, err := decimal.New(filter.Limit, 0)
		if err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrNew")
			return nil, 0, 0, err
		}
		pagesDecimal, err := totalDecimal.Quo(perPageDecimal)
		if err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrQuo")
			return nil, 0, 0, err
		}
		pages, _, _ = pagesDecimal.Ceil(0).Int64(0)
		offset := (filter.Page - 1) * filter.Limit
		_, _ = builder.WriteString(" LIMIT ")
		_, _ = builder.WriteString(strconv.FormatInt(filter.Limit, 10))
		_, _ = builder.WriteString(" OFFSET ")
		_, _ = builder.WriteString(strconv.FormatInt(offset, 10))
	}
	rows, err := q.dbRead.Query(ctx, builder.String(), params...)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrQuery")
		return nil, 0, 0, err
	}
	defer rows.Close()
	var response []*productModel.Product
	for rows.Next() {
		var product productModel.Product
		if err = rows.Scan(
			&product.RowNo,
			&product.ID,
			&product.CompanyID,
			&product.CategoryID,
			&product.Name,
			&product.Slug,
			&product.UOM,
			&product.Stock,
			&product.Price,
			&product.CreatedBy,
			&product.CreatedAt,
			&product.UpdatedBy,
			&product.UpdatedAt,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, 0, 0, err
		}
		response = append(response, &product)
	}
	return response, total, pages, nil
}

func (q *productQuery) CreateProduct(ctx context.Context, request *productModel.Product) (*productModel.Product, error) {
	ctxt := "ProductQuery-CreateProduct"
	productID, productSqID, _, err := helper.GenerateUniqueID()
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrGenerateUniqueID")
		return nil, err
	}
	now := time.Now()
	var response productModel.Product
	if err = q.dbWrite.QueryRow(
		ctx,
		`INSERT INTO products (
			_id
			, id
			, company_id
			, category_id
			, name
			, slug
			, uom
			, stock
			, price
			, created_by
			, created_at
			, updated_by
			, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $10, $11)
		RETURNING id
			, company_id
			, category_id
			, name
			, slug
			, uom
			, stock
			, price
			, created_by
			, created_at
			, updated_by
			, updated_at`,
		productID,
		productSqID,
		request.CompanyID,
		request.CategoryID,
		request.Name,
		request.Slug,
		request.UOM,
		request.Stock,
		request.Price,
		request.CreatedBy,
		now,
	).Scan(
		&response.ID,
		&response.CompanyID,
		&response.CategoryID,
		&response.Name,
		&response.Slug,
		&response.UOM,
		&response.Stock,
		&response.Price,
		&response.CreatedBy,
		&response.CreatedAt,
		&response.UpdatedBy,
		&response.UpdatedAt,
	); err != nil {
		var pgxErr *pgconn.PgError
		if errors.As(err, &pgxErr) &&
			pgxErr.Code == pgerrcode.UniqueViolation {
			switch pgxErr.ConstraintName {
			case "products_lower_company_id_idx":
				err = productModel.ErrUniqueNameViolation
			case "products_slug_company_id_idx":
				err = productModel.ErrUniqueSlugViolation
			}
		} else {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		}
		return nil, err
	}
	return &response, nil
}

func (q *productQuery) UpdateProduct(ctx context.Context, request *productModel.Product) error {
	ctxt := "ProductQuery-UpdateProduct"
	now := time.Now()
	err := q.dbWrite.QueryRow(
		ctx,
		`UPDATE products SET
			category_id = $1
			, name = $2
			, slug = $3
			, uom = $4
			, stock = $5
			, price = $6
			, updated_by = $7
			, updated_at = $8
		WHERE id = $9
		RETURNING id
			, company_id
			, category_id
			, name
			, slug
			, uom
			, stock
			, price
			, created_by
			, created_at
			, updated_by
			, updated_at`,
		request.CategoryID,
		request.Name,
		request.Slug,
		request.UOM,
		request.Stock,
		request.Price,
		request.UpdatedBy,
		now,
		request.ID,
	).Scan(
		&request.ID,
		&request.CompanyID,
		&request.CategoryID,
		&request.Name,
		&request.Slug,
		&request.UOM,
		&request.Stock,
		&request.Price,
		&request.CreatedBy,
		&request.CreatedAt,
		&request.UpdatedBy,
		&request.UpdatedAt,
	)
	if err != nil {
		var pgxErr *pgconn.PgError
		if errors.As(err, &pgxErr) &&
			pgxErr.Code == pgerrcode.UniqueViolation {
			switch pgxErr.ConstraintName {
			case "products_lower_company_id_idx":
				err = productModel.ErrUniqueNameViolation
			case "products_slug_company_id_idx":
				err = productModel.ErrUniqueSlugViolation
			}
		} else {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		}
	}
	return err
}
