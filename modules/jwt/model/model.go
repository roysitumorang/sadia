package model

import (
	"time"
)

type (
	JsonWebToken struct {
		ID        string    `json:"string"`
		Token     string    `json:"token"`
		AccountID string    `json:"account_id"`
		CreatedAt time.Time `json:"created_at"`
		ExpiredAt time.Time `json:"expired_at"`
	}

	Filter struct {
		AccountIDs,
		Tokens []string
		PaginationURL string
		Limit,
		Page int64
	}

	FilterOption func(q *Filter)
)

func NewFilter(options ...FilterOption) *Filter {
	filter := &Filter{}
	for _, option := range options {
		option(filter)
	}
	return filter
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
