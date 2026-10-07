package model

import (
	"errors"
	"net/url"
	"strings"
	"time"
)

const (
	StatusOnGoing uint8 = iota
	StatusClosed
)

type (
	Session struct {
		RowNo            uint64      `json:"row_no,omitempty" form:"-"`
		ID               uint64      `json:"id,string" form:"-"`
		CompanyID        uint64      `json:"company_id,string" form:"-"`
		Date             string      `json:"date" form:"date"`
		Status           uint8       `json:"status" form:"-"`
		CashboxValue     uint64      `json:"cashbox_value" form:"cashbox_value"`
		CashboxNote      string      `json:"cashbox_note" form:"cashbox_note"`
		TransactionValue uint64      `json:"transaction_value" form:"-"`
		SpendingValue    uint64      `json:"spending_value" form:"-"`
		Spendings        []*Spending `json:"spendings" form:"-"`
		CreatedBy        uint64      `json:"created_by,string" form:"-"`
		CreatedAt        time.Time   `json:"created_at" form:"-"`
		ClosedBy         *uint64     `json:"closed_by,string" form:"-"`
		ClosedAt         *time.Time  `json:"closed_at" form:"-"`
	}

	Spending struct {
		ID          uint64    `json:"id,string" form:"-"`
		SessionID   uint64    `json:"-" form:"-"`
		Description string    `json:"description" form:"description"`
		Value       uint64    `json:"value" form:"value"`
		CreatedBy   uint64    `json:"created_by,string"`
		CreatedAt   time.Time `json:"-" form:"-"`
	}

	Filter struct {
		SessionIDs,
		CompanyIDs []uint64
		Date,
		Keyword,
		PaginationURL string
		Limit,
		Page int64
		UrlValues url.Values
	}

	FilterOption func(q *Filter)
)

var (
	ErrUniqueDateViolation = errors.New("date: already exists")
)

func (q *Session) Validate() error {
	if q.Date == "" {
		return errors.New("date: is required")
	}
	_, err := time.Parse(time.DateOnly, q.Date)
	return err
}

func (q *Session) CalculateTotalSpendings() {
	q.SpendingValue = 0
	for _, lineItem := range q.Spendings {
		q.SpendingValue += lineItem.Value
	}
}

func (q *Spending) Validate() error {
	if q.Description = strings.TrimSpace(q.Description); q.Description == "" {
		return errors.New("description: is required")
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

func WithSessionIDs(sessionIDs ...uint64) FilterOption {
	return func(q *Filter) {
		q.SessionIDs = sessionIDs
	}
}

func WithCompanyIDs(companyIDs ...uint64) FilterOption {
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
