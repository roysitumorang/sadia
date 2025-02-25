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
		_, _ = builder.WriteString("s.id IN (")
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
	if len(filter.StoreIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("s.store_id IN (")
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
		_, _ = builder.WriteString(
			`EXISTS(
				SELECT 1
				FROM stores st
				WHERE st.id = s.store_id
					AND st.company_id IN (`,
		)
		for i, companyID := range filter.CompanyIDs {
			params = append(params, companyID)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString("))")
		conditions = append(conditions, builder.String())
	}
	if filter.Date != "" {
		params = append(params, filter.Date)
		builder.Reset()
		_, _ = builder.WriteString("s.date = $")
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
		conditions = append(conditions, builder.String())
	}
	if filter.Keyword != "" {
		builder.Reset()
		_, _ = builder.WriteString("%%")
		_, _ = builder.WriteString(strings.ToLower(filter.Keyword))
		_, _ = builder.WriteString("%%")
		params = append(params, builder.String())
		_, _ = builder.WriteString(
			`EXISTS(
				SELECT 1
				FROM stores st
				WHERE st.id = s.store_id
					AND LOWER(st.name) LIKE $`,
		)
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
		_, _ = builder.WriteString("))")
		conditions = append(conditions, builder.String())
	}
	builder.Reset()
	_, _ = builder.WriteString(
		`SELECT COUNT(1)
		FROM sessions s`,
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
		, s.store_id
		, s.date
		, s.status
		, s.cashbox_value
		, s.cashbox_note
		, s.take_money_value
		, s.created_by
		, s.created_at
		, s.closed_at`,
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
	builder.Reset()
	_, _ = builder.WriteString(
		`SELECT
			id
			, session_id
			, description
			, value
			, created_by
			, created_at
		FROM session_take_money_line_items
		WHERE session_id IN (`,
	)
	params = make([]any, 0)
	var response []*sessionModel.Session
	mapSessionOffsets := map[string]int{}
	for rows.Next() {
		session := sessionModel.Session{
			TakeMoneyLineItems: []*sessionModel.TakeMoneyLineItem{},
		}
		if err = rows.Scan(
			&session.ID,
			&session.StoreID,
			&session.Date,
			&session.Status,
			&session.CashboxValue,
			&session.CashboxNote,
			&session.TakeMoneyValue,
			&session.CreatedBy,
			&session.CreatedAt,
			&session.ClosedAt,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, 0, 0, err
		}
		response = append(response, &session)
		mapSessionOffsets[session.ID] = len(response)
		params = append(params, session.ID)
		n := len(params)
		if n > 1 {
			_, _ = builder.WriteString(",")
		}
		_, _ = builder.WriteString("$")
		_, _ = builder.WriteString(strconv.Itoa(n))
	}
	_, _ = builder.WriteString(") ORDER BY _id")
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
		var takeMoneyLineItem sessionModel.TakeMoneyLineItem
		if err = rows.Scan(
			&takeMoneyLineItem.ID,
			&takeMoneyLineItem.SessionID,
			&takeMoneyLineItem.Description,
			&takeMoneyLineItem.Value,
			&takeMoneyLineItem.CreatedBy,
			&takeMoneyLineItem.CreatedAt,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, 0, 0, err
		}
		if offset, ok := mapSessionOffsets[takeMoneyLineItem.SessionID]; ok {
			response[offset].TakeMoneyLineItems = append(
				response[offset].TakeMoneyLineItems,
				&takeMoneyLineItem,
			)
		}
	}
	return response, total, pages, nil
}

func (q *sessionQuery) CreateSession(ctx context.Context, tx pgx.Tx, request *sessionModel.NewSession) (*sessionModel.Session, error) {
	ctxt := "SessionQuery-CreateSession"
	sessionID, sessionSqID, _, err := helper.GenerateUniqueID()
	if err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrGenerateUniqueID")
		return nil, err
	}
	now := time.Now()
	response := sessionModel.Session{
		TakeMoneyLineItems: []*sessionModel.TakeMoneyLineItem{},
	}
	if err = tx.QueryRow(
		ctx,
		`INSERT INTO sessions (
			_id
			, id
			, store_id
			, date
			, status
			, cashbox_value
			, cashbox_note
			, created_by
			, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (date, created_by) DO UPDATE SET
			date = EXCLUDED.date
			, created_by = EXCLUDED.created_by
		RETURNING id
			, store_id
			, date
			, status
			, cashbox_value
			, cashbox_note
			, take_money_value
			, created_by
			, created_at
			, closed_at`,
		sessionID,
		sessionSqID,
		request.StoreID,
		now.In(helper.LoadTimeZone()).Format(time.DateOnly),
		sessionModel.StatusOnGoing,
		request.CashboxValue,
		request.CashboxNote,
		request.CreatedBy,
		now,
	).Scan(
		&response.ID,
		&response.StoreID,
		&response.Date,
		&response.Status,
		&response.CashboxValue,
		&response.CashboxNote,
		&response.TakeMoneyValue,
		&response.CreatedBy,
		&response.CreatedAt,
		&response.ClosedAt,
	); err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		var pgxErr *pgconn.PgError
		if errors.As(err, &pgxErr) &&
			pgxErr.Code == pgerrcode.UniqueViolation &&
			pgxErr.ConstraintName == "sessions_date_created_by_idx" {
			err = sessionModel.ErrUniqueDateViolation
		} else {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		}
		return nil, err
	}
	rows, err := tx.Query(
		ctx,
		`SELECT
			id
			, session_id
			, description
			, value
			, created_by
			, created_at
		FROM session_take_money_line_items
		WHERE session_id = $1
		ORDER BY _id`,
		response.ID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	if err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrQuery")
		return nil, err
	}
	for rows.Next() {
		var takeMoneyLineItem sessionModel.TakeMoneyLineItem
		if err = rows.Scan(
			&takeMoneyLineItem.ID,
			&takeMoneyLineItem.SessionID,
			&takeMoneyLineItem.Description,
			&takeMoneyLineItem.Value,
			&takeMoneyLineItem.CreatedBy,
			&takeMoneyLineItem.CreatedAt,
		); err != nil {
			if errRollback := tx.Rollback(ctx); errRollback != nil {
				helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
			}
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, err
		}
		response.TakeMoneyLineItems = append(response.TakeMoneyLineItems, &takeMoneyLineItem)
	}
	return &response, nil
}

func (q *sessionQuery) UpdateSession(ctx context.Context, tx pgx.Tx, request *sessionModel.Session) error {
	ctxt := "SessionQuery-UpdateSession"
	now := time.Now()
	if err := tx.QueryRow(
		ctx,
		`UPDATE sessions SET
			status = $1
			, take_money_value = $2
			, closed_at = $3
		WHERE id = $4
		RETURNING id
			, store_id
			, date
			, status
			, cashbox_value
			, cashbox_note
			, take_money_value
			, created_by
			, created_at
			, closed_at`,
		sessionModel.StatusClosed,
		request.TakeMoneyValue,
		now,
		request.ID,
	).Scan(
		&request.ID,
		&request.StoreID,
		&request.Date,
		&request.Status,
		&request.CashboxValue,
		&request.CashboxNote,
		&request.TakeMoneyValue,
		&request.CreatedBy,
		&request.CreatedAt,
		&request.ClosedAt,
	); err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		return err
	}
	if len(request.TakeMoneyLineItems) == 0 {
		return nil
	}
	params := []any{request.ID, request.CreatedBy, now}
	var builder strings.Builder
	_, _ = builder.WriteString(
		`INSERT INTO session_take_money_line_items (
			_id
			, id
			, session_id
			, description
			, value
			, created_by
			, created_at
		) VALUES `,
	)
	for i, lineItem := range request.TakeMoneyLineItems {
		lineItemID, lineItemSqID, _, err := helper.GenerateUniqueID()
		if err != nil {
			if errRollback := tx.Rollback(ctx); errRollback != nil {
				helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
			}
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrGenerateUniqueID")
			return err
		}
		params = append(params, lineItemID, lineItemSqID, lineItem.Description, lineItem.Value)
		n := len(params)
		if i > 0 {
			_, _ = builder.WriteString(",")
		}
		_, _ = builder.WriteString("($")
		_, _ = builder.WriteString(strconv.Itoa(n - 3))
		_, _ = builder.WriteString(",$")
		_, _ = builder.WriteString(strconv.Itoa(n - 2))
		_, _ = builder.WriteString(",$1,$")
		_, _ = builder.WriteString(strconv.Itoa(n - 1))
		_, _ = builder.WriteString(",$")
		_, _ = builder.WriteString(strconv.Itoa(n))
		_, _ = builder.WriteString(",$2,$3)")
	}
	_, _ = builder.WriteString(
		` RETURNING id
			, session_id
			, description
			, value
			, created_by
			, created_at`,
	)
	rows, err := tx.Query(ctx, builder.String(), params)
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
	request.TakeMoneyLineItems = []*sessionModel.TakeMoneyLineItem{}
	for rows.Next() {
		var takeMoneyLineItem sessionModel.TakeMoneyLineItem
		if err = rows.Scan(
			&takeMoneyLineItem.ID,
			&takeMoneyLineItem.SessionID,
			&takeMoneyLineItem.Description,
			&takeMoneyLineItem.Value,
			&takeMoneyLineItem.CreatedBy,
			&takeMoneyLineItem.CreatedAt,
		); err != nil {
			if errRollback := tx.Rollback(ctx); errRollback != nil {
				helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
			}
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return err
		}
		request.TakeMoneyLineItems = append(request.TakeMoneyLineItems, &takeMoneyLineItem)
	}
	return nil
}
