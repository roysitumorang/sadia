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
	sessionModel "github.com/roysitumorang/sadia/modules/session/model"
	"go.uber.org/zap"
)

type (
	sessionQuery struct {
		dbRead,
		dbWrite *pgxpool.Pool
	}
)

func New(
	dbRead,
	dbWrite *pgxpool.Pool,
) SessionQuery {
	return &sessionQuery{
		dbRead:  dbRead,
		dbWrite: dbWrite,
	}
}

func (q *sessionQuery) FindSessions(ctx context.Context, filter *sessionModel.Filter) ([]*sessionModel.Session, int64, int64, error) {
	ctxt := "SessionQuery-FindSessions"
	var (
		params     []any
		conditions []string
		builder    strings.Builder
	)
	if len(filter.SessionIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("id IN (")
		for i, sessionID := range filter.SessionIDs {
			params = append(params, sessionID)
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
		_, _ = builder.WriteString(
			`company_id IN (`,
		)
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
	if filter.Date != "" {
		params = append(params, filter.Date)
		builder.Reset()
		_, _ = builder.WriteString("date = $")
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
		conditions = append(conditions, builder.String())
	}
	if filter.Keyword != "" {
		builder.Reset()
		_, _ = builder.WriteString("%")
		_, _ = builder.WriteString(strings.ToLower(filter.Keyword))
		_, _ = builder.WriteString("%")
		params = append(params, builder.String())
		n := strconv.Itoa(len(params))
		builder.Reset()
		_, _ = builder.WriteString("date::varchar LIKE $")
		_, _ = builder.WriteString(n)
		conditions = append(conditions, builder.String())
	}
	builder.Reset()
	_, _ = builder.WriteString(
		`SELECT COUNT(1)
		FROM sessions`,
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
		, date::text
		, status
		, cashbox_value
		, cashbox_note
		, transaction_value
		, spending_value
		, created_by
		, created_at
		, closed_by
		, closed_at`,
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
	builder.Reset()
	_, _ = builder.WriteString(
		`SELECT
			id
			, session_id
			, description
			, value
			, created_by
			, created_at
		FROM spendings
		WHERE session_id IN (`,
	)
	params = make([]any, 0)
	var response []*sessionModel.Session
	mapSessionOffsets := map[string]int{}
	for rows.Next() {
		session := sessionModel.Session{
			Spendings: []*sessionModel.Spending{},
		}
		if err = rows.Scan(
			&session.RowNo,
			&session.ID,
			&session.CompanyID,
			&session.Date,
			&session.Status,
			&session.CashboxValue,
			&session.CashboxNote,
			&session.TransactionValue,
			&session.SpendingValue,
			&session.CreatedBy,
			&session.CreatedAt,
			&session.ClosedBy,
			&session.ClosedAt,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, 0, 0, err
		}
		response = append(response, &session)
		mapSessionOffsets[session.ID] = len(response) - 1
		params = append(params, session.ID)
		n := len(params)
		if n > 1 {
			_, _ = builder.WriteString(",")
		}
		_, _ = builder.WriteString("$")
		_, _ = builder.WriteString(strconv.Itoa(n))
	}
	_, _ = builder.WriteString(") ORDER BY id")
	if len(response) == 0 {
		return nil, 0, 0, nil
	}
	rows, err = q.dbRead.Query(ctx, builder.String(), params...)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrQuery")
		return nil, 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var spending sessionModel.Spending
		if err = rows.Scan(
			&spending.ID,
			&spending.SessionID,
			&spending.Description,
			&spending.Value,
			&spending.CreatedBy,
			&spending.CreatedAt,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, 0, 0, err
		}
		if offset, ok := mapSessionOffsets[spending.SessionID]; ok {
			response[offset].Spendings = append(
				response[offset].Spendings,
				&spending,
			)
		}
	}
	return response, total, pages, nil
}

func (q *sessionQuery) CreateSession(ctx context.Context, tx pgx.Tx, request *sessionModel.Session) (*sessionModel.Session, error) {
	ctxt := "SessionQuery-CreateSession"
	now := time.Now()
	response := sessionModel.Session{
		Spendings: []*sessionModel.Spending{},
	}
	if err := tx.QueryRow(
		ctx,
		`INSERT INTO sessions (
			company_id
			, date
			, status
			, cashbox_value
			, cashbox_note
			, transaction_value
			, spending_value
			, created_by
			, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (date, company_id) DO UPDATE SET
			date = EXCLUDED.date
			, company_id = EXCLUDED.company_id
		RETURNING id
			, company_id
			, date::text
			, status
			, cashbox_value
			, cashbox_note
			, transaction_value
			, spending_value
			, created_by
			, created_at
			, closed_by
			, closed_at`,
		request.CompanyID,
		now.In(helper.LoadTimeZone()).Format(time.DateOnly),
		sessionModel.StatusOnGoing,
		request.CashboxValue,
		request.CashboxNote,
		0,
		0,
		request.CreatedBy,
		now,
	).Scan(
		&response.ID,
		&response.CompanyID,
		&response.Date,
		&response.Status,
		&response.CashboxValue,
		&response.CashboxNote,
		&response.TransactionValue,
		&response.SpendingValue,
		&response.CreatedBy,
		&response.CreatedAt,
		&response.ClosedBy,
		&response.ClosedAt,
	); err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		var pgxErr *pgconn.PgError
		if errors.As(err, &pgxErr) &&
			pgxErr.Code == pgerrcode.UniqueViolation &&
			pgxErr.ConstraintName == "sessions_date_company_id_idx" {
			err = sessionModel.ErrUniqueDateViolation
		} else {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		}
		return nil, err
	}
	return &response, nil
}

func (q *sessionQuery) UpdateSession(ctx context.Context, tx pgx.Tx, request *sessionModel.Session) error {
	ctxt := "SessionQuery-UpdateSession"
	if err := tx.QueryRow(
		ctx,
		`UPDATE sessions SET
			status = $1
			, transaction_value = $2
			, spending_value = $3
			, closed_by = $4
			, closed_at = $5
		WHERE id = $6
		RETURNING id
			, company_id
			, date::text
			, status
			, cashbox_value
			, cashbox_note
			, transaction_value
			, spending_value
			, created_by
			, created_at
			, closed_by
			, closed_at`,
		request.Status,
		request.TransactionValue,
		request.SpendingValue,
		request.ClosedBy,
		request.ClosedAt,
		request.ID,
	).Scan(
		&request.ID,
		&request.CompanyID,
		&request.Date,
		&request.Status,
		&request.CashboxValue,
		&request.CashboxNote,
		&request.TransactionValue,
		&request.SpendingValue,
		&request.CreatedBy,
		&request.CreatedAt,
		&request.ClosedBy,
		&request.ClosedAt,
	); err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		return err
	}
	request.Spendings = []*sessionModel.Spending{}
	rows, err := tx.Query(
		ctx,
		`SELECT
			id
			, session_id
			, description
			, value
			, created_by
			, created_at
		FROM spendings
		WHERE session_id = $1
		ORDER BY id`,
		request.ID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	if err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrQuery")
		return err
	}
	for rows.Next() {
		var spending sessionModel.Spending
		if err = rows.Scan(
			&spending.ID,
			&spending.SessionID,
			&spending.Description,
			&spending.Value,
			&spending.CreatedBy,
			&spending.CreatedAt,
		); err != nil {
			if errRollback := tx.Rollback(ctx); errRollback != nil {
				helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
			}
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return err
		}
		request.Spendings = append(request.Spendings, &spending)
	}
	return nil
}

func (q *sessionQuery) CreateSpending(ctx context.Context, tx pgx.Tx, request *sessionModel.Spending) error {
	ctxt := "SessionQuery-CreateSpending"
	now := time.Now()
	_, err := tx.Exec(
		ctx,
		`INSERT INTO spendings (
			session_id
			, description
			, value
			, created_by
			, created_at
		) VALUES ($1, $2, $3, $4, $5)`,
		request.SessionID,
		request.Description,
		request.Value,
		request.CreatedBy,
		now,
	)
	if err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		return err
	}
	if _, err = tx.Exec(
		ctx,
		`WITH s AS (
			SELECT
				session_id
				, SUM(value) AS total_value
			FROM spendings
			WHERE session_id = $1
			GROUP BY session_id
		)
		UPDATE sessions SET
			spending_value = s.total_value
		FROM s
		WHERE id = s.session_id`,
		request.SessionID,
	); err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		return err
	}
	return nil
}
