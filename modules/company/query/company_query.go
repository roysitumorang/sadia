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
	"github.com/roysitumorang/sadia/models"
	companyModel "github.com/roysitumorang/sadia/modules/company/model"
	"go.uber.org/zap"
)

type (
	companyQuery struct {
		dbRead,
		dbWrite *pgxpool.Pool
	}
)

func New(
	dbRead,
	dbWrite *pgxpool.Pool,
) CompanyQuery {
	return &companyQuery{
		dbRead:  dbRead,
		dbWrite: dbWrite,
	}
}

func (q *companyQuery) FindCompanies(ctx context.Context, filter *companyModel.Filter) ([]*companyModel.Company, int64, int64, error) {
	ctxt := "CompanyQuery-FindCompanies"
	var (
		params     []any
		conditions []string
		builder    strings.Builder
	)
	if len(filter.CompanyIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("c.id IN (")
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
	if len(filter.StatusList) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("c.status IN (")
		for i, status := range filter.StatusList {
			params = append(params, status)
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
		FROM companies c`,
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
		, c.name
		, c.slug
		, c.status
		, c.created_by
		, c.created_at
		, c.updated_by
		, c.updated_at
		, c.deactivated_by
		, c.deactivated_at
		, c.deactivation_reason`,
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
	var response []*companyModel.Company
	for rows.Next() {
		var company companyModel.Company
		if err = rows.Scan(
			&company.RowNo,
			&company.ID,
			&company.Name,
			&company.Slug,
			&company.Status,
			&company.CreatedBy,
			&company.CreatedAt,
			&company.UpdatedBy,
			&company.UpdatedAt,
			&company.DeactivatedBy,
			&company.DeactivatedAt,
			&company.DeactivationReason,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, 0, 0, err
		}
		response = append(response, &company)
	}
	return response, total, pages, nil
}

func (q *companyQuery) CreateCompany(ctx context.Context, tx pgx.Tx, request *companyModel.NewCompany) (*companyModel.Company, error) {
	ctxt := "CompanyQuery-CreateCompany"
	companyID, companySqID, _, err := helper.GenerateUniqueID()
	if err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrGenerateUniqueID")
		return nil, err
	}
	now := time.Now()
	var response companyModel.Company
	if err = tx.QueryRow(
		ctx,
		`INSERT INTO companies (
			_id
			, id
			, name
			, slug
			, status
			, created_by
			, created_at
			, updated_by
			, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $6, $7)
		RETURNING id
			, name
			, slug
			, status
			, created_by
			, created_at
			, updated_by
			, updated_at
			, deactivated_by
			, deactivated_at
			, deactivation_reason`,
		companyID,
		companySqID,
		request.Name,
		companySqID,
		models.StatusUnconfirmed,
		request.CreatedBy,
		now,
	).Scan(
		&response.ID,
		&response.Name,
		&response.Slug,
		&response.Status,
		&response.CreatedBy,
		&response.CreatedAt,
		&response.UpdatedBy,
		&response.UpdatedAt,
		&response.DeactivatedBy,
		&response.DeactivatedAt,
		&response.DeactivationReason,
	); err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		var pgxErr *pgconn.PgError
		if errors.As(err, &pgxErr) &&
			pgxErr.Code == pgerrcode.UniqueViolation &&
			pgxErr.ConstraintName == "companies_slug_key" {
			err = companyModel.ErrUniqueSlugViolation
		} else {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		}
		return nil, err
	}
	return &response, nil
}

func (q *companyQuery) UpdateCompany(ctx context.Context, tx pgx.Tx, request *companyModel.Company) error {
	ctxt := "CompanyQuery-UpdateCompany"
	err := tx.QueryRow(
		ctx,
		`UPDATE companies SET
			name = $1
			, slug = $2
			, status = $3
			, updated_by = $4
			, updated_at = $5
		WHERE id = $6
		RETURNING id
			, name
			, slug
			, status
			, created_by
			, created_at
			, updated_by
			, updated_at
			, deactivated_by
			, deactivated_at
			, deactivation_reason`,
		request.Name,
		request.Slug,
		request.Status,
		request.UpdatedBy,
		request.UpdatedAt,
		request.ID,
	).Scan(
		&request.ID,
		&request.Name,
		&request.Slug,
		&request.Status,
		&request.CreatedBy,
		&request.CreatedAt,
		&request.UpdatedBy,
		&request.UpdatedAt,
		&request.DeactivatedBy,
		&request.DeactivatedAt,
		&request.DeactivationReason,
	)
	if err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		var pgxErr *pgconn.PgError
		if errors.As(err, &pgxErr) &&
			pgxErr.Code == pgerrcode.UniqueViolation &&
			pgxErr.ConstraintName == "companies_slug_key" {
			err = companyModel.ErrUniqueSlugViolation
		} else {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		}
	}
	return err
}
