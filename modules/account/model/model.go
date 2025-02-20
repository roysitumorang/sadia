package model

import (
	"time"
)

const (
	AccountTypeAdmin = iota
	AccountTypeUser
)

const (
	StatusUnconfirmed = iota
	StatusActive
	StatusDeactivated = -1
)

type (
	Account struct {
		ID                     int64      `json:"-"`
		PID                    string     `json:"id"`
		AccountType            uint8      `json:"account_type"`
		Status                 int8       `json:"status"`
		Name                   string     `json:"name"`
		Username               string     `json:"username"`
		Email                  *string    `json:"email"`
		UnconfirmedEmail       *string    `json:"-"`
		EmailConfirmationToken *string    `json:"-"`
		EmailConfirmedAt       *time.Time `json:"-"`
		Phone                  string     `json:"phone"`
		UnconfirmedPhone       *string    `json:"-"`
		PhoneConfirmationToken *string    `json:"-"`
		PhoneConfirmedAt       *time.Time `json:"-"`
		EncryptedPassword      *string    `json:"-"`
		PasswordResetToken     *string    `json:"-"`
		LoginCount             uint       `json:"login_count"`
		CurrentLoginAt         *time.Time `json:"current_login_at"`
		CurrentLoginIP         *string    `json:"current_login_ip"`
		LastLoginAt            *time.Time `json:"last_login_at"`
		LastLoginIP            *string    `json:"last_login_ip"`
		CreatedAt              time.Time  `json:"-"`
		UpdatedAt              time.Time  `json:"-"`
		DeactivatedAt          *time.Time `json:"-"`
		DeactivationReason     *string    `json:"-"`
	}

	Filter struct {
		AccountIDs []int64
		Login,
		Keyword,
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

func WithLogin(login string) FilterOption {
	return func(q *Filter) {
		q.Login = login
	}
}

func WithAccountIDs(accountIDs ...int64) FilterOption {
	return func(q *Filter) {
		q.AccountIDs = accountIDs
	}
}

func WithKeyword(Keyword string) FilterOption {
	return func(q *Filter) {
		q.Keyword = Keyword
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
