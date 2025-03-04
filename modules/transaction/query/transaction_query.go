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
	transactionModel "github.com/roysitumorang/sadia/modules/transaction/model"
	"go.uber.org/zap"
)

type (
	transactionQuery struct {
		dbRead,
		dbWrite *pgxpool.Pool
	}
)

func New(
	dbRead,
	dbWrite *pgxpool.Pool,
) TransactionQuery {
	return &transactionQuery{
		dbRead:  dbRead,
		dbWrite: dbWrite,
	}
}

func (q *transactionQuery) FindTransactions(ctx context.Context, filter *transactionModel.Filter) ([]*transactionModel.Transaction, int64, int64, error) {
	ctxt := "TransactionQuery-FindTransactions"
	var (
		params     []any
		conditions []string
		builder    strings.Builder
	)
	if len(filter.TransactionIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("t.id IN (")
		for i, transactionID := range filter.TransactionIDs {
			params = append(params, transactionID)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString(")")
		conditions = append(conditions, builder.String())
	}
	if len(filter.SessionIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString("t.session_id IN (")
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
		_, _ = builder.WriteString(
			`EXISTS(
				SELECT 1
				FROM sessions s
				WHERE s.id = t.session_id
					AND s.store_id IN (`,
		)
		for i, storeID := range filter.StoreIDs {
			params = append(params, storeID)
			if i > 0 {
				_, _ = builder.WriteString(",")
			}
			_, _ = builder.WriteString("$")
			_, _ = builder.WriteString(strconv.Itoa(len(params)))
		}
		_, _ = builder.WriteString("))")
		conditions = append(conditions, builder.String())
	}
	if len(filter.CompanyIDs) > 0 {
		builder.Reset()
		_, _ = builder.WriteString(
			`EXISTS(
				SELECT 1
				FROM sessions s
				JOIN stores st ON s.store_id = st.id
				WHERE s.id = t.session_id
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
	if filter.Keyword != "" {
		builder.Reset()
		_, _ = builder.WriteString("%%")
		_, _ = builder.WriteString(strings.ToUpper(filter.Keyword))
		_, _ = builder.WriteString("%%")
		params = append(params, builder.String())
		_, _ = builder.WriteString("t.reference_no LIKE $")
		_, _ = builder.WriteString(strconv.Itoa(len(params)))
		_, _ = builder.WriteString("))")
		conditions = append(conditions, builder.String())
	}
	builder.Reset()
	_, _ = builder.WriteString(
		`SELECT COUNT(1)
		FROM transactions t`,
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
		`ROW_NUMBER() OVER (ORDER BY -t._id) AS row_no
		, t.id
		, t.session_id
		, t.reference_no
		, t.subtotal
		, t.discount
		, t.tax_rate
		, t.tax
		, t.total
		, t.payment_method
		, t.created_by
		, t.created_at`,
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
	builder.Reset()
	_, _ = builder.WriteString(
		`SELECT
			ROW_NUMBER() OVER (ORDER BY -_id) AS row_no,
			, id
			, transaction_id
			, product_id
			, product_name
			, product_uom
			, quantity
			, price
			, subtotal
			, created_by
			, created_at
		FROM transaction_line_items
		WHERE transaction_id IN (`,
	)
	params = make([]any, 0)
	var response []*transactionModel.Transaction
	mapTransactionOffsets := map[string]int{}
	for rows.Next() {
		transaction := transactionModel.Transaction{
			LineItems: []*transactionModel.LineItem{},
		}
		if err = rows.Scan(
			&transaction.RowNo,
			&transaction.ID,
			&transaction.SessionID,
			&transaction.ReferenceNo,
			&transaction.Subtotal,
			&transaction.Discount,
			&transaction.TaxRate,
			&transaction.Tax,
			&transaction.Total,
			&transaction.PaymentMethod,
			&transaction.CreatedBy,
			&transaction.CreatedAt,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, 0, 0, err
		}
		response = append(response, &transaction)
		mapTransactionOffsets[transaction.ID] = len(response)
		params = append(params, transaction.ID)
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
		var lineItem transactionModel.LineItem
		if err = rows.Scan(
			&lineItem.ID,
			&lineItem.TransactionID,
			&lineItem.ProductID,
			&lineItem.ProductName,
			&lineItem.ProductUOM,
			&lineItem.Quantity,
			&lineItem.Price,
			&lineItem.Subtotal,
		); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, 0, 0, err
		}
		if offset, ok := mapTransactionOffsets[lineItem.TransactionID]; ok {
			response[offset].LineItems = append(
				response[offset].LineItems,
				&lineItem,
			)
		}
	}
	return response, total, pages, nil
}

func (q *transactionQuery) CreateTransaction(ctx context.Context, tx pgx.Tx, request *transactionModel.Transaction) (*transactionModel.Transaction, error) {
	ctxt := "TransactionQuery-CreateTransaction"
	transactionID, transactionSqID, _, err := helper.GenerateUniqueID()
	if err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrGenerateUniqueID")
		return nil, err
	}
	now := time.Now()
	response := transactionModel.Transaction{
		LineItems: []*transactionModel.LineItem{},
	}
	if err = tx.QueryRow(
		ctx,
		`INSERT INTO transactions (
			_id
			, id
			, session_id
			, reference_no
			, subtotal
			, discount
			, tax_rate
			, tax
			, total
			, payment_method
			, created_by
			, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id
			, session_id
			, reference_no
			, subtotal
			, discount
			, tax_rate
			, tax
			, total
			, payment_method
			, created_by
			, created_at`,
		transactionID,
		transactionSqID,
		request.SessionID,
		request.ReferenceNo,
		request.Subtotal,
		request.Discount,
		request.TaxRate,
		request.Tax,
		request.Total,
		request.PaymentMethod,
		request.CreatedBy,
		now,
	).Scan(
		&response.ID,
		&response.SessionID,
		&response.ReferenceNo,
		&response.Subtotal,
		&response.Discount,
		&response.TaxRate,
		&response.Tax,
		&response.Total,
		&response.PaymentMethod,
		&response.CreatedBy,
		&response.CreatedAt,
	); err != nil {
		if errRollback := tx.Rollback(ctx); errRollback != nil {
			helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
		}
		var pgxErr *pgconn.PgError
		if errors.As(err, &pgxErr) &&
			pgxErr.Code == pgerrcode.UniqueViolation &&
			pgxErr.ConstraintName == "transactions_reference_no_key" {
			err = transactionModel.ErrUniqueReferenceNoViolation
		} else {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		}
		return nil, err
	}
	if len(request.LineItems) == 0 {
		return &response, nil
	}
	params := []any{response.ID}
	var builder strings.Builder
	_, _ = builder.WriteString(
		`INSERT INTO transaction_line_items (
			_id
			, id
			, transaction_id
			, product_id
			, product_name
			, product_uom
			, quantity
			, price
			, subtotal
		) VALUES `,
	)
	for i, lineItem := range request.LineItems {
		lineItemID, lineItemSqID, _, err := helper.GenerateUniqueID()
		if err != nil {
			if errRollback := tx.Rollback(ctx); errRollback != nil {
				helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
			}
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrGenerateUniqueID")
			return nil, err
		}
		params = append(
			params,
			lineItemID,
			lineItemSqID,
			lineItem.ProductID,
			lineItem.ProductName,
			lineItem.ProductUOM,
			lineItem.Quantity,
			lineItem.Price,
			lineItem.Subtotal,
		)
		n := len(params)
		if i > 0 {
			_, _ = builder.WriteString(",")
		}
		_, _ = builder.WriteString("($")
		_, _ = builder.WriteString(strconv.Itoa(n - 6))
		_, _ = builder.WriteString(",$")
		_, _ = builder.WriteString(strconv.Itoa(n - 5))
		_, _ = builder.WriteString(",$1,$")
		_, _ = builder.WriteString(strconv.Itoa(n - 4))
		_, _ = builder.WriteString(",$")
		_, _ = builder.WriteString(strconv.Itoa(n - 3))
		_, _ = builder.WriteString(",$")
		_, _ = builder.WriteString(strconv.Itoa(n - 2))
		_, _ = builder.WriteString(",$")
		_, _ = builder.WriteString(strconv.Itoa(n - 1))
		_, _ = builder.WriteString(",$")
		_, _ = builder.WriteString(strconv.Itoa(n))
		_, _ = builder.WriteString(")")
	}
	_, _ = builder.WriteString(
		` RETURNING id
			, transaction_id
			, product_id
			, product_name
			, product_uom
			, quantity
			, price
			, subtotal`,
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
		return nil, err
	}
	for rows.Next() {
		var lineItem transactionModel.LineItem
		if err = rows.Scan(
			&lineItem.ID,
			&lineItem.TransactionID,
			&lineItem.ProductID,
			&lineItem.ProductName,
			&lineItem.ProductUOM,
			&lineItem.Quantity,
			&lineItem.Price,
			&lineItem.Subtotal,
		); err != nil {
			if errRollback := tx.Rollback(ctx); errRollback != nil {
				helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
			}
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return nil, err
		}
		response.LineItems = append(response.LineItems, &lineItem)
	}
	return &response, nil
}
