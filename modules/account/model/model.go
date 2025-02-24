package model

import (
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	customErrors "github.com/roysitumorang/sadia/errors"
	"github.com/roysitumorang/sadia/helper"
)

const (
	AccountTypeAdmin uint8 = iota
	AccountTypeUser
)

const (
	StatusUnconfirmed int8 = iota
	StatusActive
	StatusDeactivated int8 = -1
)

const (
	AdminLevelSuperAdmin int8 = iota
	AdminLevelAdmin
)

type (
	Account struct {
		ID                      string     `json:"id"`
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
		AccountIDs []string
		StatusList []int
		Login,
		Keyword,
		ConfirmationToken,
		EmailConfirmationToken,
		PhoneConfirmationToken,
		LoginUnlockToken,
		ResetPasswordToken,
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
		Login          string `json:"login"`
		Base64Password string `json:"password"`
		Password       string `json:"-"`
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

	ForgotPassword struct {
		Login string `json:"login"`
	}

	ResetPassword struct {
		Base64Password string `json:"password"`
		Password       string `json:"-"`
	}

	ChangePassword struct {
		Base64OldPassword string `json:"old_password"`
		OldPassword       string `json:"-"`
		Base64NewPassword string `json:"new_password"`
		NewPassword       string `json:"-"`
	}

	ChangeUsername struct {
		Base64Password string `json:"password"`
		Password       string `json:"-"`
		Username       string `json:"username"`
	}

	ChangeEmail struct {
		Base64Password string `json:"password"`
		Password       string `json:"-"`
		Email          string `json:"email"`
	}

	ChangePhone struct {
		Base64Password string `json:"password"`
		Password       string `json:"-"`
		Phone          string `json:"phone"`
	}
)

var (
	phoneNumberRegex                         = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
	ErrLoginFailed                           = customErrors.New(fiber.StatusBadRequest, "login failed")
	ErrUniqueUsernameViolation               = errors.New("username: already exists")
	ErrUniqueEmailViolation                  = errors.New("email: already exists")
	ErrUniquePhoneViolation                  = errors.New("phone: already exists")
	ErrUniqueConfirmationTokenViolation      = errors.New("confirmation_token: already exists")
	ErrUniqueEmailConfirmationTokenViolation = errors.New("email_confirmation_token: already exists")
	ErrUniquePhoneConfirmationTokenViolation = errors.New("phone_confirmation_token: already exists")
	ErrUniqueResetPasswordTokenViolation     = errors.New("reset_password_token: already exists")
	ErrUniqueLoginUnlockTokenViolation       = errors.New("login_unlock_token: already exists")
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

func WithStatusList(statusList ...int) FilterOption {
	return func(q *Filter) {
		q.StatusList = statusList
	}
}

func WithLogin(login string) FilterOption {
	return func(q *Filter) {
		q.Login = login
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

func WithResetPasswordToken(resetPasswordToken string) FilterOption {
	return func(q *Filter) {
		q.ResetPasswordToken = resetPasswordToken
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

func (q *NewAccount) Validate() error {
	if q.AccountType != AccountTypeAdmin &&
		q.AccountType != AccountTypeUser {
		return fmt.Errorf(
			"account_type: should be either %d or %d",
			AccountTypeAdmin,
			AccountTypeUser,
		)
	}
	if q.Name = strings.TrimSpace(q.Name); q.Name == "" {
		return errors.New("name: is required")
	}
	if q.Username = strings.ToLower(strings.TrimSpace(q.Username)); q.Username == "" {
		return errors.New("username: is required")
	}
	if q.Email != nil {
		if *q.Email = strings.ToLower(strings.TrimSpace(*q.Email)); *q.Email != "" {
			if _, err := mail.ParseAddress(*q.Email); err != nil {
				return errors.New("email: invalid address")
			}
		} else {
			q.Email = nil
		}
	}
	if q.Phone != nil {
		if *q.Phone = strings.TrimSpace(*q.Phone); *q.Phone != "" {
			if phoneNumberRegex.Find(helper.String2ByteSlice(*q.Phone)) == nil {
				return errors.New("phone: invalid number")
			}
		} else {
			q.Phone = nil
		}
	}
	return nil
}

func (q *Deactivation) Validate() error {
	if q.Reason = strings.TrimSpace(q.Reason); q.Reason == "" {
		return errors.New("reason: is required")
	}
	return nil
}

func (q *LoginRequest) Validate() error {
	if q.Login = strings.TrimSpace(q.Login); q.Login == "" {
		return errors.New("login: is required")
	}
	if q.Base64Password = strings.TrimSpace(q.Base64Password); q.Password == "" {
		return errors.New("password: is required")
	}
	password, err := helper.Base64Decode(q.Base64Password)
	if err != nil {
		return fmt.Errorf("password: %s", err.Error())
	}
	q.Password = password
	return nil
}

func (q *Confirmation) Validate() error {
	if q.Name = strings.TrimSpace(q.Name); q.Name == "" {
		return errors.New("name: is required")
	}
	if q.Username = strings.ToLower(strings.TrimSpace(q.Username)); q.Username == "" {
		return errors.New("username: is required")
	}
	if q.Email != nil {
		if *q.Email = strings.ToLower(strings.TrimSpace(*q.Email)); *q.Email != "" {
			if _, err := mail.ParseAddress(*q.Email); err != nil {
				return errors.New("email: invalid address")
			}
		} else {
			q.Email = nil
		}
	}
	if q.Phone != nil {
		if *q.Phone = strings.TrimSpace(*q.Phone); *q.Phone != "" {
			if phoneNumberRegex.Find(helper.String2ByteSlice(*q.Phone)) == nil {
				return errors.New("phone: invalid number")
			}
		} else {
			q.Phone = nil
		}
	}
	if q.Base64Password = strings.TrimSpace(q.Base64Password); q.Base64Password == "" {
		return errors.New("password: is required")
	}
	password, err := helper.Base64Decode(q.Base64Password)
	if err != nil {
		return fmt.Errorf("password: %s", err.Error())
	}
	q.Password = password
	if !helper.ValidPassword(q.Password) {
		return errors.New("password: min 8 characters & should contain uppercase/lowercase/number/symbol")
	}
	return nil
}

func (q *ForgotPassword) Validate() error {
	if q.Login = strings.TrimSpace(q.Login); q.Login == "" {
		return errors.New("login: is required")
	}
	return nil
}

func (q *ResetPassword) Validate() error {
	if q.Base64Password = strings.TrimSpace(q.Base64Password); q.Base64Password == "" {
		return errors.New("password: is required")
	}
	password, err := helper.Base64Decode(q.Base64Password)
	if err != nil {
		return fmt.Errorf("password: %s", err.Error())
	}
	q.Password = password
	if !helper.ValidPassword(q.Password) {
		return errors.New("password: min 8 characters & should contain uppercase/lowercase/number/symbol")
	}
	return nil
}

func (q *ChangePassword) Validate() error {
	if q.Base64OldPassword = strings.TrimSpace(q.Base64OldPassword); q.Base64OldPassword == "" {
		return errors.New("old_password: is required")
	}
	oldPassword, err := helper.Base64Decode(q.Base64OldPassword)
	if err != nil {
		return fmt.Errorf("old_password: %s", err.Error())
	}
	q.OldPassword = oldPassword
	if q.Base64NewPassword = strings.TrimSpace(q.Base64NewPassword); q.Base64NewPassword == "" {
		return errors.New("new_password: is required")
	}
	newPassword, err := helper.Base64Decode(q.Base64NewPassword)
	if err != nil {
		return fmt.Errorf("new_password: %s", err.Error())
	}
	q.NewPassword = newPassword
	if !helper.ValidPassword(q.NewPassword) {
		return errors.New("new_password: min 8 characters & should contain uppercase/lowercase/number/symbol")
	}
	return nil
}

func (q *ChangeUsername) Validate() error {
	if q.Base64Password = strings.TrimSpace(q.Base64Password); q.Base64Password == "" {
		return errors.New("password: is required")
	}
	password, err := helper.Base64Decode(q.Base64Password)
	if err != nil {
		return fmt.Errorf("password: %s", err.Error())
	}
	q.Password = password
	if q.Username = strings.ToLower(strings.TrimSpace(q.Username)); q.Username == "" {
		return errors.New("username: is required")
	}
	return nil
}

func (q *ChangeEmail) Validate() error {
	if q.Base64Password = strings.TrimSpace(q.Base64Password); q.Base64Password == "" {
		return errors.New("password: is required")
	}
	password, err := helper.Base64Decode(q.Base64Password)
	if err != nil {
		return fmt.Errorf("password: %s", err.Error())
	}
	q.Password = password
	if q.Email = strings.ToLower(strings.TrimSpace(q.Email)); q.Email == "" {
		return errors.New("email: is required")
	}
	if _, err = mail.ParseAddress(q.Email); err != nil {
		return errors.New("email: invalid address")
	}
	return nil
}

func (q *ChangePhone) Validate() error {
	if q.Base64Password = strings.TrimSpace(q.Base64Password); q.Base64Password == "" {
		return errors.New("password: is required")
	}
	password, err := helper.Base64Decode(q.Base64Password)
	if err != nil {
		return fmt.Errorf("password: %s", err.Error())
	}
	q.Password = password
	if q.Phone = strings.TrimSpace(q.Phone); q.Phone != "" {
		return errors.New("phone: is required")
	}
	if phoneNumberRegex.Find(helper.String2ByteSlice(q.Phone)) == nil {
		return errors.New("phone: invalid number")
	}
	return nil
}
