package model

import (
	"net/url"
	"time"
)

type (
	JsonWebToken struct {
		RowNo     uint64    `json:"row_no,omitempty"`
		ID        int64     `json:"string"`
		Token     string    `json:"token"`
		AccountID int64     `json:"account_id"`
		CreatedAt time.Time `json:"created_at"`
		ExpiredAt time.Time `json:"expired_at"`
	}

	Filter struct {
		JwtIDs,
		AccountIDs []int64
		Tokens        []string
		PaginationURL string
		Limit,
		Page int64
		UrlValues url.Values
	}

	FilterOption func(q *Filter)

	DeleteFilter struct {
		MaxExpiredAt time.Time
		AccountID,
		CompanyID int64
		JwtIDs []int64
	}

	DeleteFilterOption func(q *DeleteFilter)
)

func NewFilter(options ...FilterOption) *Filter {
	filter := &Filter{UrlValues: url.Values{}}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func WithJwtIDs(jwtIDs ...int64) FilterOption {
	return func(q *Filter) {
		q.JwtIDs = jwtIDs
	}
}

func WithAccountIDs(accountIDs ...int64) FilterOption {
	return func(q *Filter) {
		q.AccountIDs = accountIDs
	}
}

func WithTokens(tokens ...string) FilterOption {
	return func(q *Filter) {
		q.Tokens = tokens
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

func NewDeleteFilter(options ...DeleteFilterOption) *DeleteFilter {
	filter := &DeleteFilter{}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func WithDeleteMaxExpiredAt(maxExpiredAt time.Time) DeleteFilterOption {
	return func(q *DeleteFilter) {
		q.MaxExpiredAt = maxExpiredAt
	}
}

func WithDeleteAccountID(accountID int64) DeleteFilterOption {
	return func(q *DeleteFilter) {
		q.AccountID = accountID
	}
}

func WithDeleteCompanyID(companyID int64) DeleteFilterOption {
	return func(q *DeleteFilter) {
		q.CompanyID = companyID
	}
}

func WithDeleteJwtIDs(jwtIDs ...int64) DeleteFilterOption {
	return func(q *DeleteFilter) {
		q.JwtIDs = jwtIDs
	}
}
