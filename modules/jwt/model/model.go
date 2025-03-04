package model

import (
	"net/url"
	"time"
)

type (
	JsonWebToken struct {
		RowNo     uint64    `json:"row_no,omitempty"`
		ID        string    `json:"string"`
		Token     string    `json:"token"`
		AccountID string    `json:"account_id"`
		CreatedAt time.Time `json:"created_at"`
		ExpiredAt time.Time `json:"expired_at"`
	}

	Filter struct {
		JwtIDs,
		AccountIDs,
		Tokens []string
		PaginationURL string
		Limit,
		Page int64
		UrlValues url.Values
	}

	FilterOption func(q *Filter)

	DeleteFilter struct {
		MaxExpiredAt time.Time
		AccountID,
		CompanyID string
		JwtIDs []string
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

func WithJwtIDs(jwtIDs ...string) FilterOption {
	return func(q *Filter) {
		q.JwtIDs = jwtIDs
	}
}

func WithAccountIDs(accountIDs ...string) FilterOption {
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

func WithDeleteAccountID(accountID string) DeleteFilterOption {
	return func(q *DeleteFilter) {
		q.AccountID = accountID
	}
}

func WithDeleteCompanyID(companyID string) DeleteFilterOption {
	return func(q *DeleteFilter) {
		q.CompanyID = companyID
	}
}

func WithDeleteJwtIDs(jwtIDs ...string) DeleteFilterOption {
	return func(q *DeleteFilter) {
		q.JwtIDs = jwtIDs
	}
}
