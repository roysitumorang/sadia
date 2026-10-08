package repositories

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/govalues/decimal"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	"go.uber.org/zap"
)

type LogRepository interface {
	FindLogs(ctx context.Context, filter *models.LogFilter) ([]*models.Log, int64, int64, error)
	CreateLog(ctx context.Context, tx pgx.Tx, request *models.Log) (*models.Log, error)
}

type logRepository struct {
	dbRead,
	dbWrite *pgxpool.Pool
}

func NewLogRepository(
	dbRead,
	dbWrite *pgxpool.Pool,
) LogRepository {
	return &logRepository{
		dbRead:  dbRead,
		dbWrite: dbWrite,
	}
}

func (q *logRepository) FindLogs(ctx context.Context, filter *models.LogFilter) ([]*models.Log, int64, int64, error) {
	ctxt := "LogRepository-FindLogs"
	var (
		params     []any
		conditions []string
		builder    strings.Builder
	)
	if len(filter.LogIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("id IN (")
		for i, logID := range filter.LogIDs {
			params = append(params, logID)
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
		_, _ = builder.WriteString("company_id IN (")
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
	if len(filter.TableIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("table_id IN (")
		for i, tableID := range filter.TableIDs {
			params = append(params, tableID)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	if len(filter.TableNames) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("table_name IN (")
		for i, tableName := range filter.TableNames {
			params = append(params, tableName)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	builder.Reset()
	_, _ = builder.WriteString(
		`SELECT COUNT(1)
		FROM logs`,
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
		`ROW_NUMBER() OVER (ORDER BY id DESC) AS row_no
		, id
		, company_id
		, table_name
		, table_id
		, action
		, changes
		, created_by
		, created_at`,
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
	var response []*models.Log
	for rows.Next() {
		var log models.Log
		if err = rows.Scan(
			&log.RowNo,
			&log.ID,
			&log.CompanyID,
			&log.TableName,
			&log.TableID,
			&log.Action,
			&log.Changes,
			&log.CreatedBy,
			&log.CreatedAt,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, 0, 0, err
		}
		response = append(response, &log)
	}
	if err = rows.Err(); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrErr")
		return nil, 0, 0, err
	}
	return response, total, pages, nil
}

func (q *logRepository) CreateLog(ctx context.Context, tx pgx.Tx, request *models.Log) (*models.Log, error) {
	ctxt := "LogRepository-CreateLog"
	var response models.Log
	if err := tx.QueryRow(
		ctx,
		`INSERT INTO logs (
			id
			, company_id
			, table_id
			, table_name
			, action
			, changes
			, created_by
			, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
			, company_id
			, table_id
			, table_name
			, action
			, changes
			, created_by
			, created_at`,
		helper.GenerateSnowflakeID(),
		request.CompanyID,
		request.TableID,
		request.TableName,
		request.Action,
		request.Changes,
		request.CreatedBy,
		request.CreatedAt,
	).Scan(
		&response.ID,
		&response.CompanyID,
		&response.TableID,
		&response.TableName,
		&response.Action,
		&response.Changes,
		&response.CreatedBy,
		&response.CreatedAt,
	); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		return nil, err
	}
	return &response, nil
}
