package model

import (
	"errors"
	"fmt"
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
		ID                 string               `json:"id"`
		StoreID            string               `json:"store_id"`
		Date               string               `json:"date"`
		Status             uint8                `json:"status"`
		CashboxValue       int64                `json:"cashbox_value"`
		CashboxNote        string               `json:"cashbox_note"`
		TransactionValue   int64                `json:"transaction_value"`
		TakeMoneyValue     int64                `json:"take_money_value"`
		TakeMoneyLineItems []*TakeMoneyLineItem `json:"take_money_line_items"`
		CreatedBy          string               `json:"created_by"`
		CreatedAt          time.Time            `json:"created_at"`
		ClosedAt           *time.Time           `json:"closed_at"`
	}

	TakeMoneyLineItem struct {
		ID          string    `json:"id"`
		SessionID   string    `json:"-"`
		Description string    `json:"description"`
		Value       int64     `json:"value"`
		CreatedBy   string    `json:"-"`
		CreatedAt   time.Time `json:"-"`
	}

	Filter struct {
		SessionIDs,
		StoreIDs,
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
		StoreID      string `json:"store_id"`
		CashboxValue int64  `json:"cashbox_value"`
		CashboxNote  string `json:"cashbox_note"`
		CreatedBy    string `json:"-"`
	}

	CloseSession struct {
		TakeMoneyValue     int64                           `json:"-"`
		TakeMoneyLineItems []CloseSessionTakeMoneyLineItem `json:"take_money_line_items"`
	}

	CloseSessionTakeMoneyLineItem struct {
		Description string `json:"description"`
		Value       int64  `json:"value"`
	}
)

var (
	ErrUniqueDateViolation = errors.New("date: already exists")
)

func (q *NewSession) Validate() error {
	if q.StoreID = strings.TrimSpace(q.StoreID); q.StoreID == "" {
		return errors.New("store_id: is required")
	}
	if q.CashboxValue == 0 {
		return errors.New("cashbox_value: requires a postive integer")
	}
	return nil
}

func (q *CloseSession) Validate() error {
	q.TakeMoneyValue = 0
	for i, lineItem := range q.TakeMoneyLineItems {
		if lineItem.Description == "" {
			return fmt.Errorf("take_money_line_items[%d].description is required", i)
		}
		if lineItem.Value == 0 {
			return fmt.Errorf("take_money_line_items[%d].value is required", i)
		}
		q.TakeMoneyValue += lineItem.Value
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

func WithStoreIDs(storeIDs ...string) FilterOption {
	return func(q *Filter) {
		q.StoreIDs = storeIDs
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
