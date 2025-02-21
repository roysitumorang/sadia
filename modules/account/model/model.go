package model

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	customErrors "github.com/roysitumorang/sadia/errors"
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
		ID                      int64      `json:"-"`
		UID                     string     `json:"uid"`
		AccountType             uint8      `json:"account_type"`
		Status                  int8       `json:"status"`
		Name                    string     `json:"name"`
		Username                string     `json:"username"`
		ConfirmationToken       *string    `json:"-"`
		ConfirmedAt             *time.Time `json:"confirmed_at"`
		Email                   *string    `json:"email"`
		UnconfirmedEmail        *string    `json:"unconfirmed_email"`
		EmailConfirmationToken  *string    `json:"-"`
		EmailConfirmationSentAt *time.Time `json:"-"`
		EmailConfirmedAt        *time.Time `json:"-"`
		Phone                   *string    `json:"phone"`
		UnconfirmedPhone        *string    `json:"unconfirmed_phone"`
		PhoneConfirmationToken  *string    `json:"-"`
		PhoneConfirmationSentAt *time.Time `json:"-"`
		PhoneConfirmedAt        *time.Time `json:"-"`
		EncryptedPassword       *string    `json:"-"`
		LastPasswordChange      *time.Time `json:"last_password_change"`
		ResetPasswordToken      *string    `json:"-"`
		ResetPasswordSentAt     *time.Time `json:"-"`
		LoginCount              uint       `json:"login_count"`
		CurrentLoginAt          *time.Time `json:"current_login_at"`
		CurrentLoginIP          *string    `json:"current_login_ip"`
		LastLoginAt             *time.Time `json:"last_login_at"`
		LastLoginIP             *string    `json:"last_login_ip"`
		LoginFailedAttempts     int        `json:"login_failed_attempts"`
		LoginUnlockToken        *string    `json:"-"`
		LoginLockedAt           *time.Time `json:"login_locked_at"`
		CreatedBy               *string    `json:"-"`
		CreatedAt               time.Time  `json:"-"`
		UpdatedAt               time.Time  `json:"-"`
		DeactivatedBy           *string    `json:"-"`
		DeactivatedAt           *time.Time `json:"-"`
		DeactivationReason      *string    `json:"-"`
	}

	Filter struct {
		AccountUIDs []string
		StatusList  []int
		Login,
		Keyword,
		ConfirmationToken,
		EmailConfirmationToken,
		PhoneConfirmationToken,
		LoginUnlockToken,
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
		Phone       *string `json:"phone"`
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
		Name           string  `json:"name"`
		Username       string  `json:"username"`
		Email          *string `json:"email"`
		Phone          *string `json:"phone"`
		Base64Password string  `json:"password"`
		Password       string  `json:"-"`
	}
)

var (
	ErrLoginFailed                           = customErrors.New(fiber.StatusBadRequest, "login failed")
	ErrUniqueUsernameViolation               = errors.New("username: already exists")
	ErrUniqueEmailViolation                  = errors.New("email: already exists")
	ErrUniquePhoneViolation                  = errors.New("phone: already exists")
	ErrUniqueConfirmationTokenViolation      = errors.New("confirmation_token: already exists")
	ErrUniqueEmailConfirmationTokenViolation = errors.New("email_confirmation_token: already exists")
	ErrUniquePhoneConfirmationTokenViolation = errors.New("phone_confirmation_token: already exists")
	ErrUniqueLoginUnlockTokenViolation       = errors.New("login_unlock_token: already exists")
)

func (q LoginRequest) DecodePassword() (string, error) {
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

func WithEmailConfirmationToken(emailConfirmationToken string) FilterOption {
	return func(q *Filter) {
		q.EmailConfirmationToken = emailConfirmationToken
	}
}

func WithPhoneConfirmationToken(phoneConfirmationToken string) FilterOption {
	return func(q *Filter) {
		q.PhoneConfirmationToken = phoneConfirmationToken
	}
}

func WithLoginUnlockToken(loginUnlockToken string) FilterOption {
	return func(q *Filter) {
		q.LoginUnlockToken = loginUnlockToken
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
