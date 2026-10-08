package models

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

type Session struct {
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

type Spending struct {
	ID          uint64    `json:"id,string" form:"-"`
	SessionID   uint64    `json:"-" form:"-"`
	Description string    `json:"description" form:"description"`
	Value       uint64    `json:"value" form:"value"`
	CreatedBy   uint64    `json:"created_by,string"`
	CreatedAt   time.Time `json:"-" form:"-"`
}

func (q *Spending) Validate() error {
	if q.Description = strings.TrimSpace(q.Description); q.Description == "" {
		return errors.New("description: is required")
	}
	return nil
}

type SessionFilter struct {
	SessionIDs,
	CompanyIDs []uint64
	Date,
	Keyword,
	PaginationURL string
	Limit,
	Page int64
	UrlValues url.Values
}

type SessionFilterOption func(q *SessionFilter)

func NewSessionFilter(options ...SessionFilterOption) *SessionFilter {
	filter := &SessionFilter{UrlValues: url.Values{}}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func SessionWithSessionIDs(sessionIDs ...uint64) SessionFilterOption {
	return func(q *SessionFilter) {
		q.SessionIDs = sessionIDs
	}
}

func SessionWithCompanyIDs(companyIDs ...uint64) SessionFilterOption {
	return func(q *SessionFilter) {
		q.CompanyIDs = companyIDs
	}
}

func SessionWithKeyword(keyword string) SessionFilterOption {
	return func(q *SessionFilter) {
		q.Keyword = keyword
	}
}

func SessionWithPaginationURL(paginationURL string) SessionFilterOption {
	return func(q *SessionFilter) {
		q.PaginationURL = paginationURL
	}
}

func SessionWithLimit(limit int64) SessionFilterOption {
	return func(q *SessionFilter) {
		q.Limit = limit
	}
}

func SessionWithPage(page int64) SessionFilterOption {
	return func(q *SessionFilter) {
		q.Page = page
	}
}

func SessionWithUrlValues(urlValues url.Values) SessionFilterOption {
	return func(q *SessionFilter) {
		q.UrlValues = urlValues
	}
}

var ErrUniqueSessionDateViolation = errors.New("date: already exists")
