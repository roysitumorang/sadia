package models

import (
	"net/url"
	"time"
)

type JsonWebToken struct {
	RowNo     uint64    `json:"row_no,omitempty"`
	ID        uint64    `json:"id,string"`
	Token     string    `json:"token"`
	AccountID uint64    `json:"account_id,string"`
	CreatedAt time.Time `json:"created_at"`
	ExpiredAt time.Time `json:"expired_at"`
}

type JwtFilter struct {
	JwtIDs,
	AccountIDs []uint64
	Tokens        []string
	PaginationURL string
	Limit,
	Page int64
	UrlValues url.Values
}

type JwtFilterOption func(q *JwtFilter)

func NewJwtFilter(options ...JwtFilterOption) *JwtFilter {
	filter := &JwtFilter{UrlValues: url.Values{}}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func JwtWithJwtIDs(jwtIDs ...uint64) JwtFilterOption {
	return func(q *JwtFilter) {
		q.JwtIDs = jwtIDs
	}
}

func JwtWithAccountIDs(accountIDs ...uint64) JwtFilterOption {
	return func(q *JwtFilter) {
		q.AccountIDs = accountIDs
	}
}

func JwtWithTokens(tokens ...string) JwtFilterOption {
	return func(q *JwtFilter) {
		q.Tokens = tokens
	}
}

func JwtWithPaginationURL(paginationURL string) JwtFilterOption {
	return func(q *JwtFilter) {
		q.PaginationURL = paginationURL
	}
}

func JwtWithLimit(limit int64) JwtFilterOption {
	return func(q *JwtFilter) {
		q.Limit = limit
	}
}

func JwtWithPage(page int64) JwtFilterOption {
	return func(q *JwtFilter) {
		q.Page = page
	}
}

func JwtWithUrlValues(urlValues url.Values) JwtFilterOption {
	return func(q *JwtFilter) {
		q.UrlValues = urlValues
	}
}

type JwtDeleteFilter struct {
	MaxExpiredAt time.Time
	AccountID,
	CompanyID uint64
	JwtIDs []uint64
}

type JwtDeleteFilterOption func(q *JwtDeleteFilter)

func NewJwtDeleteFilter(options ...JwtDeleteFilterOption) *JwtDeleteFilter {
	filter := &JwtDeleteFilter{}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func JwtWithDeleteMaxExpiredAt(maxExpiredAt time.Time) JwtDeleteFilterOption {
	return func(q *JwtDeleteFilter) {
		q.MaxExpiredAt = maxExpiredAt
	}
}

func JwtWithDeleteAccountID(accountID uint64) JwtDeleteFilterOption {
	return func(q *JwtDeleteFilter) {
		q.AccountID = accountID
	}
}

func JwtWithDeleteCompanyID(companyID uint64) JwtDeleteFilterOption {
	return func(q *JwtDeleteFilter) {
		q.CompanyID = companyID
	}
}

func JwtWithDeleteJwtIDs(jwtIDs ...uint64) JwtDeleteFilterOption {
	return func(q *JwtDeleteFilter) {
		q.JwtIDs = jwtIDs
	}
}
