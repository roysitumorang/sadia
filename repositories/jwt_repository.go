package repositories

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
	"github.com/roysitumorang/sadia/models"
	"go.uber.org/zap"
)

type JwtRepository interface {
	CreateJWT(ctx context.Context, tx pgx.Tx, accountID uint64) (*models.JsonWebToken, error)
	DeleteJWTs(ctx context.Context, tx pgx.Tx, filter *models.JwtDeleteFilter) (int64, error)
	FindJWTs(ctx context.Context, filter *models.JwtFilter) ([]*models.JsonWebToken, int64, int64, error)
}

type jwtRepository struct {
	dbRead,
	dbWrite *pgxpool.Pool
}

func NewJwtRepository(
	dbRead,
	dbWrite *pgxpool.Pool,
) JwtRepository {
	return &jwtRepository{
		dbRead:  dbRead,
		dbWrite: dbWrite,
	}
}

func (q *jwtRepository) CreateJWT(ctx context.Context, tx pgx.Tx, accountID uint64) (*models.JsonWebToken, error) {
	ctxt := "JwtRepository-CreateJWT"
	now := time.Now()
	expiredAt := now.Add(helper.GetAccessTokenAge())
	token := helper.GenerateUniqueID()
	var response models.JsonWebToken
	err := tx.QueryRow(
		ctx,
		`INSERT INTO json_web_tokens (
			id
			, token
			, account_id
			, created_at
			, expired_at
		) VALUES ($1, $2, $3, $4, $5)
		RETURNING id
			, token
			, account_id
			, created_at
			, expired_at`,
		helper.GenerateSnowflakeID(),
		token,
		accountID,
		now,
		expiredAt,
	).Scan(
		&response.ID,
		&response.Token,
		&response.AccountID,
		&response.CreatedAt,
		&response.ExpiredAt,
	)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		return nil, err
	}
	return &response, nil
}

func (q *jwtRepository) FindJWTs(ctx context.Context, filter *models.JwtFilter) ([]*models.JsonWebToken, int64, int64, error) {
	ctxt := "JwtRepository-FindJWTs"
	var (
		params     []any
		conditions []string
		builder    strings.Builder
	)
	if len(filter.JwtIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("id IN (")
		for i, jwtID := range filter.JwtIDs {
			params = append(params, jwtID)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
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
	query = strings.ReplaceAll(query, "COUNT(1)", "ROW_NUMBER() OVER (ORDER BY id DESC) AS row_no, id, token, account_id, created_at, expired_at")
	builder.Reset()
	_, _ = builder.WriteString(query)
	_, _ = builder.WriteString(" ORDER BY id DESC")
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
	var response []*models.JsonWebToken
	for rows.Next() {
		var jwt models.JsonWebToken
		if err = rows.Scan(
			&jwt.RowNo,
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
	if err = rows.Err(); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrErr")
		return nil, 0, 0, err
	}
	return response, total, pages, nil
}

func (q *jwtRepository) DeleteJWTs(ctx context.Context, tx pgx.Tx, filter *models.JwtDeleteFilter) (int64, error) {
	ctxt := "JwtRepository-DeleteJWTs"
	var (
		params     []any
		conditions []string
		builder    strings.Builder
	)
	if !filter.MaxExpiredAt.IsZero() {
		params = append(params, filter.MaxExpiredAt)
		builder.Reset()
		_, _ = builder.WriteString("j.expired_at <= $")
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
		conditions = append(conditions, builder.String())
	}
	if filter.AccountID != 0 {
		params = append(params, filter.AccountID)
		builder.Reset()
		_, _ = builder.WriteString("j.account_id = $")
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
		conditions = append(conditions, builder.String())
	}
	if filter.CompanyID != 0 {
		params = append(params, filter.CompanyID)
		builder.Reset()
		_, _ = builder.WriteString(
			`EXISTS(
				SELECT 1
				FROM users u
				WHERE u.account_id = j.account_id
					AND u.company_id = $`,
		)
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	if len(filter.JwtIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("j.id IN (")
		for i, jwtID := range filter.JwtIDs {
			params = append(params, jwtID)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString(")")
		condition := builder.String()
		conditions = append(conditions, condition, strings.ReplaceAll(condition, "j.id", "j.token"))
	}
	if len(conditions) == 0 {
		return 0, nil
	}
	builder.Reset()
	_, _ = builder.WriteString("DELETE FROM json_web_tokens j WHERE")
	for i, condition := range conditions {
		if i > 0 {
			_, _ = builder.WriteString(" OR")
		}
		_, _ = builder.WriteString(" ")
		_, _ = builder.WriteString(condition)
	}
	result, err := tx.Exec(ctx, builder.String(), params...)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
	}
	return result.RowsAffected(), err
}
