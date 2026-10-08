package repositories

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/govalues/decimal"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	"go.uber.org/zap"
)

type ProductCategoryRepository interface {
	FindProductCategories(ctx context.Context, filter *models.ProductCategoryFilter) ([]*models.ProductCategory, int64, int64, error)
	CreateProductCategory(ctx context.Context, tx pgx.Tx, request *models.ProductCategory) (*models.ProductCategory, error)
	UpdateProductCategory(ctx context.Context, tx pgx.Tx, request *models.ProductCategory) (*models.ProductCategory, error)
}

type productCategoryRepository struct {
	dbRead,
	dbWrite *pgxpool.Pool
}

func NewProductCategoryRepository(
	dbRead,
	dbWrite *pgxpool.Pool,
) ProductCategoryRepository {
	return &productCategoryRepository{
		dbRead:  dbRead,
		dbWrite: dbWrite,
	}
}

func (q *productCategoryRepository) FindProductCategories(ctx context.Context, filter *models.ProductCategoryFilter) ([]*models.ProductCategory, int64, int64, error) {
	ctxt := "ProductCategoryRepository-FindProductCategories"
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
		`ROW_NUMBER() OVER (ORDER BY c.id DESC) AS row_no
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
		offset := filter.Page * filter.Limit
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
	var response []*models.ProductCategory
	for rows.Next() {
		var category models.ProductCategory
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
	if err = rows.Err(); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrErr")
		return nil, 0, 0, err
	}
	return response, total, pages, nil
}

func (q *productCategoryRepository) CreateProductCategory(ctx context.Context, tx pgx.Tx, request *models.ProductCategory) (*models.ProductCategory, error) {
	ctxt := "ProductCategoryRepository-CreateProductCategory"
	var response models.ProductCategory
	if err := tx.QueryRow(
		ctx,
		`INSERT INTO product_categories (
			id
			, company_id
			, name
			, slug
			, created_by
			, created_at
			, updated_by
			, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $5, $6)
		RETURNING id
			, company_id
			, name
			, slug
			, created_by
			, created_at
			, updated_by
			, updated_at`,
		helper.GenerateSnowflakeID(),
		request.CompanyID,
		request.Name,
		request.Slug,
		request.CreatedBy,
		request.CreatedAt,
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
		if pgxErr, ok := errors.AsType[*pgconn.PgError](err); ok &&
			pgxErr.Code == pgerrcode.UniqueViolation {
			switch pgxErr.ConstraintName {
			case "product_categories_lower_company_id_idx":
				err = models.ErrUniqueProductCategoryNameViolation
			case "product_categories_slug_company_id_idx":
				err = models.ErrUniqueProductCategorySlugViolation
			}
		} else {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		}
		return nil, err
	}
	return &response, nil
}

func (q *productCategoryRepository) UpdateProductCategory(ctx context.Context, tx pgx.Tx, request *models.ProductCategory) (*models.ProductCategory, error) {
	ctxt := "ProductCategoryRepository-UpdateProductCategory"
	var response models.ProductCategory
	err := tx.QueryRow(
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
		request.UpdatedAt,
		request.ID,
	).Scan(
		&response.ID,
		&response.CompanyID,
		&response.Name,
		&response.Slug,
		&response.CreatedBy,
		&response.CreatedAt,
		&response.UpdatedBy,
		&response.UpdatedAt,
	)
	if err != nil {
		if pgxErr, ok := errors.AsType[*pgconn.PgError](err); ok &&
			pgxErr.Code == pgerrcode.UniqueViolation {
			switch pgxErr.ConstraintName {
			case "product_categories_lower_company_id_idx":
				err = models.ErrUniqueProductCategoryNameViolation
			case "product_categories_slug_company_id_idx":
				err = models.ErrUniqueProductCategorySlugViolation
			}
		} else {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		}
		return nil, err
	}
	return &response, nil
}
