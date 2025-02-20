package model

import (
	"time"
)

type (
	JsonWebToken struct {
		ID         int64     `json:"-"`
		UID        string    `json:"uid"`
		Token      string    `json:"token"`
		AccountUID string    `json:"account_uid"`
		CreatedAt  time.Time `json:"created_at"`
		ExpiredAt  time.Time `json:"expired_at"`
	}

	Filter struct {
		AccountUIDs,
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

func WithAccountUIDs(accountUIDs ...string) FilterOption {
	return func(q *Filter) {
		q.AccountUIDs = accountUIDs
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
