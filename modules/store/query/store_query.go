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
	storeModel "github.com/roysitumorang/sadia/modules/store/model"
	"go.uber.org/zap"
)

type (
	storeQuery struct {
		dbRead,
		dbWrite *pgxpool.Pool
	}
)

func New(
	dbRead,
	dbWrite *pgxpool.Pool,
) StoreQuery {
	return &storeQuery{
		dbRead:  dbRead,
		dbWrite: dbWrite,
	}
}

func (q *storeQuery) FindStores(ctx context.Context, filter *storeModel.Filter) ([]*storeModel.Store, int64, int64, error) {
	ctxt := "StoreQuery-FindStores"
	var (
		params     []any
		conditions []string
		builder    strings.Builder
	)
	if len(filter.StoreIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("s.id IN (")
		for i, storeID := range filter.StoreIDs {
			params = append(params, storeID)
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
		_, _ = builder.WriteString("s.company_id IN (")
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
		_, _ = builder.WriteString("(LOWER(s.name) LIKE $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(" OR s.slug LIKE $")
		_, _ = builder.WriteString(n)
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	builder.Reset()
	_, _ = builder.WriteString(
		`SELECT COUNT(1)
		FROM stores s`,
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
		`s.id
		, s.company_id
		, s.name
		, s.slug
		, s.created_by
		, s.created_at
		, s.updated_by
		, s.updated_at
		, s.current_session_id`,
	)
	builder.Reset()
	_, _ = builder.WriteString(query)
	_, _ = builder.WriteString(" ORDER by -s._id")
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
	var response []*storeModel.Store
	for rows.Next() {
		var store storeModel.Store
		if err = rows.Scan(
			&store.ID,
			&store.CompanyID,
			&store.Name,
			&store.Slug,
			&store.CreatedBy,
			&store.CreatedAt,
			&store.UpdatedBy,
			&store.UpdatedAt,
			&store.CurrentSessionID,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, 0, 0, err
		}
		response = append(response, &store)
	}
	return response, total, pages, nil
}

func (q *storeQuery) CreateStore(ctx context.Context, request *storeModel.Store) (*storeModel.Store, error) {
	ctxt := "StoreQuery-CreateStore"
	storeID, storeSqID, _, err := helper.GenerateUniqueID()
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrGenerateUniqueID")
		return nil, err
	}
	now := time.Now()
	var response storeModel.Store
	if err = q.dbWrite.QueryRow(
		ctx,
		`INSERT INTO stores (
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
			, updated_at
			, current_session_id`,
		storeID,
		storeSqID,
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
		&response.CurrentSessionID,
	); err != nil {
		var pgxErr *pgconn.PgError
		if errors.As(err, &pgxErr) &&
			pgxErr.Code == pgerrcode.UniqueViolation {
			switch pgxErr.ConstraintName {
			case "stores_lower_company_id_idx":
				err = storeModel.ErrUniqueNameViolation
			case "stores_slug_company_id_idx":
				err = storeModel.ErrUniqueSlugViolation
			}
		} else {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		}
		return nil, err
	}
	return &response, nil
}

func (q *storeQuery) UpdateStore(ctx context.Context, tx pgx.Tx, request *storeModel.Store) error {
	ctxt := "StoreQuery-UpdateStore"
	now := time.Now()
	err := tx.QueryRow(
		ctx,
		`UPDATE stores SET
			name = $1
			, slug = $2
			, updated_by = $3
			, updated_at = $4
			, current_session_id = $5
		WHERE id = $6
		RETURNING id
			, company_id
			, name
			, slug
			, created_by
			, created_at
			, updated_by
			, updated_at
			, current_session_id`,
		request.Name,
		request.Slug,
		request.UpdatedBy,
		now,
		request.CurrentSessionID,
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
		&request.CurrentSessionID,
	)
	if err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		var pgxErr *pgconn.PgError
		if errors.As(err, &pgxErr) &&
			pgxErr.Code == pgerrcode.UniqueViolation {
			switch pgxErr.ConstraintName {
			case "stores_lower_company_id_idx":
				err = storeModel.ErrUniqueNameViolation
			case "stores_slug_company_id_idx":
				err = storeModel.ErrUniqueSlugViolation
			}
		} else {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		}
	}
	return err
}
