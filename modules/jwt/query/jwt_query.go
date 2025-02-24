package query

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/govalues/decimal"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/roysitumorang/sadia/helper"
	jwtModel "github.com/roysitumorang/sadia/modules/jwt/model"
	"go.uber.org/zap"
)

type (
	jwtQuery struct {
		dbRead,
		dbWrite *pgxpool.Pool
	}
)

func New(
	dbRead,
	dbWrite *pgxpool.Pool,
) JwtQuery {
	return &jwtQuery{
		dbRead:  dbRead,
		dbWrite: dbWrite,
	}
}

func (q *jwtQuery) CreateJWT(ctx context.Context, tx pgx.Tx, request jwtModel.JsonWebToken) error {
	ctxt := "JwtQuery-CreateJWT"
	_, err := tx.Exec(
		ctx,
		`INSERT INTO json_web_tokens (
			id
			, token
			, account_id
			, created_at
			, expired_at
		) VALUES ($1, $2, $3, $4, $5)`,
		request.ID,
		request.Token,
		request.AccountID,
		request.CreatedAt,
		request.ExpiredAt,
	)
	if err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
	}
	return err
}

func (q *jwtQuery) FindJWTs(ctx context.Context, filter *jwtModel.Filter) ([]*jwtModel.JsonWebToken, int64, int64, error) {
	ctxt := "JwtQuery-FindJWTs"
	var (
		params     []any
		conditions []string
		builder    strings.Builder
	)
	if len(filter.AccountIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("account_id IN (")
		for i, accountID := range filter.AccountIDs {
			params = append(params, accountID)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	if len(filter.Tokens) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("token IN (")
		for i, token := range filter.Tokens {
			params = append(params, token)
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
		FROM json_web_tokens`,
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
	query = strings.ReplaceAll(query, "COUNT(1)", "id, token, account_id, created_at, expired_at")
	builder.Reset()
	_, _ = builder.WriteString(query)
	_, _ = builder.WriteString(" ORDER by -_id")
	pages := int64(1)
	if filter.Limit > 0 {
		totalDecimal, err := decimal.New(total, 0)
		if err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrNew")
			return nil, 0, 0, err
		}
		limitDecimal, err := decimal.New(filter.Limit, 0)
		if err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrNew")
			return nil, 0, 0, err
		}
		pagesDecimal, err := totalDecimal.Quo(limitDecimal)
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
	var response []*jwtModel.JsonWebToken
	for rows.Next() {
		var jwt jwtModel.JsonWebToken
		if err = rows.Scan(
			&jwt.ID,
			&jwt.Token,
			&jwt.AccountID,
			&jwt.CreatedAt,
			&jwt.ExpiredAt,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, 0, 0, err
		}
		response = append(response, &jwt)
	}
	return response, total, pages, nil
}

func (q *jwtQuery) DeleteJWTs(ctx context.Context, tx pgx.Tx, maxExpiredAt time.Time, accountID string, jwtIDs ...string) (int64, error) {
	ctxt := "JwtQuery-DeleteJWTs"
	var (
		params     []any
		conditions []string
		builder    strings.Builder
	)
	if !maxExpiredAt.IsZero() {
		params = append(params, maxExpiredAt)
		builder.Reset()
		_, _ = builder.WriteString("expired_at <= $")
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
		conditions = append(conditions, builder.String())
	}
	if len(jwtIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("id IN (")
		for i, jwtID := range jwtIDs {
			params = append(params, jwtID)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString(")")
		condition := builder.String()
		conditions = append(conditions, condition, strings.ReplaceAll(condition, "id", "token"))
	}
	if len(conditions) == 0 {
		return 0, nil
	}
	builder.Reset()
	_, _ = builder.WriteString("DELETE FROM json_web_tokens WHERE")
	for i, condition := range conditions {
		if i > 0 {
			_, _ = builder.WriteString(" OR")
		}
		_, _ = builder.WriteString(" ")
		_, _ = builder.WriteString(condition)
	}
	result, err := tx.Exec(ctx, builder.String(), params...)
	if err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
	}
	return result.RowsAffected(), err
}
