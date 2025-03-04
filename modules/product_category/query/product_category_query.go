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
	productCategoryModel "github.com/roysitumorang/sadia/modules/product_category/model"
	"go.uber.org/zap"
)

type (
	productCategoryQuery struct {
		dbRead,
		dbWrite *pgxpool.Pool
	}
)

func New(
	dbRead,
	dbWrite *pgxpool.Pool,
) ProductCategoryQuery {
	return &productCategoryQuery{
		dbRead:  dbRead,
		dbWrite: dbWrite,
	}
}

func (q *productCategoryQuery) FindProductCategories(ctx context.Context, filter *productCategoryModel.Filter) ([]*productCategoryModel.ProductCategory, int64, int64, error) {
	ctxt := "ProductCategoryQuery-FindProductCategories"
	var (
		params     []any
		conditions []string
		builder    strings.Builder
	)
	if len(filter.ProductCategoryIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("c.id IN (")
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
		_, _ = builder.WriteString("c.company_id IN (")
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
		_, _ = builder.WriteString("(LOWER(c.name) LIKE $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR c.slug LIKE $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	builder.Reset()
	_, _ = builder.WriteString(
		`SELECT COUNT(1)
		FROM product_categories c`,
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
		`ROW_NUMBER() OVER (ORDER BY -c._id) AS row_no
		, c.id
		, c.company_id
		, c.name
		, c.slug
		, c.created_by
		, c.created_at
		, c.updated_by
		, c.updated_at`,
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
	var response []*productCategoryModel.ProductCategory
	for rows.Next() {
		var category productCategoryModel.ProductCategory
		if err = rows.Scan(
			&category.RowNo,
			&category.ID,
			&category.CompanyID,
			&category.Name,
			&category.Slug,
			&category.CreatedBy,
			&category.CreatedAt,
			&category.UpdatedBy,
			&category.UpdatedAt,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, 0, 0, err
		}
		response = append(response, &category)
	}
	return response, total, pages, nil
}

func (q *productCategoryQuery) CreateProductCategory(ctx context.Context, request *productCategoryModel.ProductCategory) (*productCategoryModel.ProductCategory, error) {
	ctxt := "ProductCategoryQuery-CreateProductCategory"
	productCategoryID, productCategorySqID, _, err := helper.GenerateUniqueID()
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrGenerateUniqueID")
		return nil, err
	}
	now := time.Now()
	var response productCategoryModel.ProductCategory
	if err = q.dbWrite.QueryRow(
		ctx,
		`INSERT INTO product_categories (
			_id
			, id
			, company_id
			, name
			, slug
			, created_by
			, created_at
			, updated_by
			, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $6, $7)
		RETURNING id
			, company_id
			, name
			, slug
			, created_by
			, created_at
			, updated_by
			, updated_at`,
		productCategoryID,
		productCategorySqID,
		request.CompanyID,
		request.Name,
		request.Slug,
		request.CreatedBy,
		now,
	).Scan(
		&response.ID,
		&response.CompanyID,
		&response.Name,
		&response.Slug,
		&response.CreatedBy,
		&response.CreatedAt,
		&response.UpdatedBy,
		&response.UpdatedAt,
	); err != nil {
		var pgxErr *pgconn.PgError
		if errors.As(err, &pgxErr) &&
			pgxErr.Code == pgerrcode.UniqueViolation {
			switch pgxErr.ConstraintName {
			case "product_categories_lower_company_id_idx":
				err = productCategoryModel.ErrUniqueNameViolation
			case "product_categories_slug_company_id_idx":
				err = productCategoryModel.ErrUniqueSlugViolation
			}
		} else {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		}
		return nil, err
	}
	return &response, nil
}

func (q *productCategoryQuery) UpdateProductCategory(ctx context.Context, request *productCategoryModel.ProductCategory) error {
	ctxt := "ProductCategoryQuery-UpdateProductCategory"
	now := time.Now()
	err := q.dbWrite.QueryRow(
		ctx,
		`UPDATE product_categories SET
			name = $1
			, slug = $2
			, updated_by = $3
			, updated_at = $4
		WHERE id = $5
		RETURNING id
			, company_id
			, name
			, slug
			, created_by
			, created_at
			, updated_by
			, updated_at`,
		request.Name,
		request.Slug,
		request.UpdatedBy,
		now,
		request.ID,
	).Scan(
		&request.ID,
		&request.CompanyID,
		&request.Name,
		&request.Slug,
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
			case "product_categories_lower_company_id_idx":
				err = productCategoryModel.ErrUniqueNameViolation
			case "product_categories_slug_company_id_idx":
				err = productCategoryModel.ErrUniqueSlugViolation
			}
		} else {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		}
	}
	return err
}
