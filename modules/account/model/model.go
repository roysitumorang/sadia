package model

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/roysitumorang/sadia/errors"
	"github.com/roysitumorang/sadia/helper"
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
		UID                    string     `json:"uid"`
		AccountType            uint8      `json:"account_type"`
		Status                 int8       `json:"status"`
		Name                   string     `json:"name"`
		Username               string     `json:"username"`
		Email                  *string    `json:"email"`
		UnconfirmedEmail       *string    `json:"unconfirmed_email"`
		EmailConfirmationToken *string    `json:"-"`
		EmailConfirmedAt       *time.Time `json:"-"`
		Phone                  *string    `json:"phone"`
		UnconfirmedPhone       *string    `json:"unconfirmed_phone"`
		PhoneConfirmationToken *string    `json:"-"`
		PhoneConfirmedAt       *time.Time `json:"-"`
		EncryptedPassword      *string    `json:"-"`
		LastPasswordChange     *time.Time `json:"last_password_change"`
		PasswordResetToken     *string    `json:"-"`
		LoginCount             uint       `json:"login_count"`
		CurrentLoginAt         *time.Time `json:"current_login_at"`
		CurrentLoginIP         *string    `json:"current_login_ip"`
		LastLoginAt            *time.Time `json:"last_login_at"`
		LastLoginIP            *string    `json:"last_login_ip"`
		CreatedBy              *string    `json:"-"`
		CreatedAt              time.Time  `json:"-"`
		UpdatedAt              time.Time  `json:"-"`
		DeactivatedBy          *string    `json:"-"`
		DeactivatedAt          *time.Time `json:"-"`
		DeactivationReason     *string    `json:"-"`
	}

	Filter struct {
		AccountUIDs []string
		StatusList  []int
		Login,
		Keyword,
		ConfirmationToken,
		PaginationURL string
		Limit,
		Page int64
	}

	FilterOption func(q *Filter)

	NewAccount struct {
		AccountType uint8   `json:"account_type"`
		Name        string  `json:"name"`
		Username    string  `json:"username"`
		Email       *string `json:"email"`
		Phone       string  `json:"phone"`
		CreatedBy   *string `json:"-"`
	}

	Deactivation struct {
		Reason string `json:"reason"`
	}

	LoginRequest struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}

	LoginResponse struct {
		IDToken   string    `json:"id_token"`
		ExpiredAt time.Time `json:"expired_at"`
		Account   *Account  `json:"account"`
	}

	Confirmation struct {
		Token    string `json:"token"`
		Password string `json:"password,omitempty"`
	}
)

var (
	ErrLoginFailed = errors.New(fiber.StatusBadRequest, "login failed")
)

func (q LoginRequest) DecodePassword() (string, error) {
	return helper.Base64Decode(q.Password)
}

func (q *Confirmation) DecodePassword() (string, error) {
	if q.Password = strings.TrimSpace(q.Password); q.Password == "" {
		return q.Password, nil
	}
	return helper.Base64Decode(q.Password)
}

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

func WithAccountUIDs(accountUIDs ...string) FilterOption {
	return func(q *Filter) {
		q.AccountUIDs = accountUIDs
	}
}

func WithKeyword(keyword string) FilterOption {
	return func(q *Filter) {
		q.Keyword = keyword
	}
}

func WithConfirmationToken(confirmationToken string) FilterOption {
	return func(q *Filter) {
		q.ConfirmationToken = confirmationToken
	}
}

func WithStatusList(statusList ...int) FilterOption {
	return func(q *Filter) {
		q.StatusList = statusList
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
