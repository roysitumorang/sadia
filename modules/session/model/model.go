package model

import (
	"errors"
	"fmt"
	"net/url"
	"time"
)

const (
	StatusOnGoing uint8 = iota
	StatusClosed
)

type (
	Session struct {
		RowNo             uint64              `json:"row_no,omitempty"`
		ID                string              `json:"id"`
		CompanyID         string              `json:"company_id"`
		Date              string              `json:"date"`
		Status            uint8               `json:"status"`
		CashboxValue      int64               `json:"cashbox_value"`
		CashboxNote       string              `json:"cashbox_note"`
		TransactionValue  int64               `json:"transaction_value"`
		SpendingValue     int64               `json:"spending_value"`
		SpendingLineItems []*SpendingLineItem `json:"spending_line_items"`
		CreatedBy         string              `json:"created_by"`
		CreatedAt         time.Time           `json:"created_at"`
		ClosedAt          *time.Time          `json:"closed_at"`
	}

	SpendingLineItem struct {
		ID          string    `json:"id"`
		SessionID   string    `json:"-"`
		Description string    `json:"description"`
		Value       int64     `json:"value"`
		CreatedAt   time.Time `json:"-"`
	}

	Filter struct {
		SessionIDs,
		CompanyIDs []string
		Date,
		Keyword,
		PaginationURL string
		Limit,
		Page int64
		UrlValues url.Values
	}

	FilterOption func(q *Filter)

	NewSession struct {
		CompanyID    string `json:"-"`
		CashboxValue int64  `json:"cashbox_value"`
		CashboxNote  string `json:"cashbox_note"`
		CreatedBy    string `json:"-"`
	}

	CloseSession struct {
		SpendingValue     int64                          `json:"-"`
		SpendingLineItems []CloseSessionSpendingLineItem `json:"spending_line_items"`
	}

	CloseSessionSpendingLineItem struct {
		Description string `json:"description"`
		Value       int64  `json:"value"`
	}
)

var (
	ErrUniqueDateViolation = errors.New("date: already exists")
)

func (q *NewSession) Validate() error {
	if q.CashboxValue < 0 {
		return errors.New("cashbox_value: requires a positive integer")
	}
	return nil
}

func (q *CloseSession) Validate() error {
	q.SpendingValue = 0
	for i, lineItem := range q.SpendingLineItems {
		if lineItem.Description == "" {
			return fmt.Errorf("spending_line_items[%d].description is required", i)
		}
		if lineItem.Value < 0 {
			return fmt.Errorf("spending_line_items[%d].value is required", i)
		}
		q.SpendingValue += lineItem.Value
	}
	return nil
}

func NewFilter(options ...FilterOption) *Filter {
	filter := &Filter{UrlValues: url.Values{}}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func WithSessionIDs(sessionIDs ...string) FilterOption {
	return func(q *Filter) {
		q.SessionIDs = sessionIDs
	}
}

func WithCompanyIDs(companyIDs ...string) FilterOption {
	return func(q *Filter) {
		q.CompanyIDs = companyIDs
	}
}

func WithKeyword(keyword string) FilterOption {
	return func(q *Filter) {
		q.Keyword = keyword
	}
}

func WithPaginationURL(paginationURL string) FilterOption {
	return func(q *Filter) {
		q.PaginationURL = paginationURL
	}
}

func WithLimit(limit int64) FilterOption {
	return func(q *Filter) {
		q.Limit = limit
	}
}

func WithPage(page int64) FilterOption {
	return func(q *Filter) {
		q.Page = page
	}
}

func WithUrlValues(urlValues url.Values) FilterOption {
	return func(q *Filter) {
		q.UrlValues = urlValues
	}
}
