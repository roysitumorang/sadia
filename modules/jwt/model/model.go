package model

import (
	"time"
)

type (
	JsonWebToken struct {
		ID        int64     `json:"-"`
		Token     string    `json:"-"`
		AccountID int64     `json:"-"`
		CreatedAt time.Time `json:"-"`
		ExpiredAt time.Time `json:"-"`
	}

	Filter struct {
		Tokens        []string
		PaginationURL string
		PerPage,
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

func WithTokens(tokens ...string) FilterOption {
	return func(q *Filter) {
		q.Tokens = tokens
	}
}

func WithPerPage(perPage int64) FilterOption {
	return func(q *Filter) {
		q.PerPage = perPage
	}
}

func WithPage(page int64) FilterOption {
	return func(q *Filter) {
		q.Page = page
	}
}
