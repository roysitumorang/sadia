package models

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/nyaruka/phonenumbers"
	customErrors "github.com/roysitumorang/sadia/errors"
	"github.com/roysitumorang/sadia/helper"
)

const (
	AdminLevelSuperAdmin uint8 = iota
	AdminLevelAdmin
)

const (
	UserLevelOwner uint8 = iota
	UserLevelStaff
)

type Account struct {
	RowNo                   uint64     `json:"row_no,omitempty"`
	ID                      uint64     `json:"id,string"`
	AccountType             uint8      `json:"account_type"`
	Status                  uint8      `json:"status"`
	Name                    string     `json:"name"`
	Username                string     `json:"username"`
	ConfirmationToken       *string    `json:"-"`
	ConfirmedAt             *time.Time `json:"confirmed_at"`
	Email                   *string    `json:"email"`
	UnconfirmedEmail        *string    `json:"unconfirmed_email"`
	EmailConfirmationToken  *string    `json:"-"`
	EmailConfirmationSentAt *time.Time `json:"email_confirmation_sent_at"`
	EmailConfirmedAt        *time.Time `json:"email_confirmed_at"`
	Phone                   *string    `json:"phone"`
	UnconfirmedPhone        *string    `json:"unconfirmed_phone"`
	PhoneConfirmationToken  *string    `json:"-"`
	PhoneConfirmationSentAt *time.Time `json:"phone_confirmation_sent_at"`
	PhoneConfirmedAt        *time.Time `json:"phone_confirmed_at"`
	EncryptedPassword       *string    `json:"-"`
	LastPasswordChange      *time.Time `json:"last_password_change"`
	ResetPasswordToken      *string    `json:"-"`
	ResetPasswordSentAt     *time.Time `json:"reset_password_sent_at"`
	LoginCount              uint       `json:"login_count"`
	CurrentLoginAt          *time.Time `json:"current_login_at"`
	CurrentLoginIP          *string    `json:"current_login_ip"`
	LastLoginAt             *time.Time `json:"last_login_at"`
	LastLoginIP             *string    `json:"last_login_ip"`
	LoginFailedAttempts     int        `json:"login_failed_attempts"`
	LoginUnlockToken        *string    `json:"-"`
	LoginLockedAt           *time.Time `json:"login_locked_at"`
	CreatedBy               *uint64    `json:"-"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
	DeactivatedBy           *uint64    `json:"-"`
	DeactivatedAt           *time.Time `json:"deactivated_at"`
	DeactivationReason      *string    `json:"-"`
}

type Admin struct {
	*Account
	AdminLevel uint8 `json:"admin_level"`
}

type User struct {
	*Account
	CompanyID uint64 `json:"company_id,string"`
	UserLevel uint8  `json:"user_level"`
}

type AccountFilter struct {
	AccountIDs,
	CompanyIDs []uint64
	StatusList,
	AccountTypes,
	AdminLevels,
	UserLevels []uint8
	Login,
	Keyword,
	Username,
	ConfirmationToken,
	Email,
	EmailConfirmationToken,
	Phone,
	PhoneConfirmationToken,
	LoginUnlockToken,
	ResetPasswordToken,
	PaginationURL string
	Limit,
	Page int64
	UrlValues url.Values
}

type AccountFilterOption func(q *AccountFilter)

func NewAccountFilter(options ...AccountFilterOption) *AccountFilter {
	filter := &AccountFilter{UrlValues: url.Values{}}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func AccountWithAccountIDs(accountIDs ...uint64) AccountFilterOption {
	return func(q *AccountFilter) {
		q.AccountIDs = accountIDs
	}
}

func AccountWithCompanyIDs(companyIDs ...uint64) AccountFilterOption {
	return func(q *AccountFilter) {
		q.CompanyIDs = companyIDs
	}
}

func AccountWithStatusList(statusList ...uint8) AccountFilterOption {
	return func(q *AccountFilter) {
		q.StatusList = statusList
	}
}

func AccountWithAccountTypes(accountTypes ...uint8) AccountFilterOption {
	return func(q *AccountFilter) {
		q.AccountTypes = accountTypes
	}
}

func AccountWithAdminLevels(adminLevels ...uint8) AccountFilterOption {
	return func(q *AccountFilter) {
		q.AdminLevels = adminLevels
	}
}

func AccountWithUserLevels(userLevels ...uint8) AccountFilterOption {
	return func(q *AccountFilter) {
		q.UserLevels = userLevels
	}
}

func AccountWithLogin(login string) AccountFilterOption {
	return func(q *AccountFilter) {
		q.Login = login
	}
}

func AccountWithKeyword(keyword string) AccountFilterOption {
	return func(q *AccountFilter) {
		q.Keyword = keyword
	}
}

func AccountWithUsername(username string) AccountFilterOption {
	return func(q *AccountFilter) {
		q.Username = username
	}
}

func AccountWithConfirmationToken(confirmationToken string) AccountFilterOption {
	return func(q *AccountFilter) {
		q.ConfirmationToken = confirmationToken
	}
}

func AccountWithEmail(email string) AccountFilterOption {
	return func(q *AccountFilter) {
		q.Email = email
	}
}

func AccountWithEmailConfirmationToken(emailConfirmationToken string) AccountFilterOption {
	return func(q *AccountFilter) {
		q.EmailConfirmationToken = emailConfirmationToken
	}
}

func AccountWithPhone(phone string) AccountFilterOption {
	return func(q *AccountFilter) {
		q.Phone = phone
	}
}

func AccountWithPhoneConfirmationToken(phoneConfirmationToken string) AccountFilterOption {
	return func(q *AccountFilter) {
		q.PhoneConfirmationToken = phoneConfirmationToken
	}
}

func AccountWithLoginUnlockToken(loginUnlockToken string) AccountFilterOption {
	return func(q *AccountFilter) {
		q.LoginUnlockToken = loginUnlockToken
	}
}

func AccountWithResetPasswordToken(resetPasswordToken string) AccountFilterOption {
	return func(q *AccountFilter) {
		q.ResetPasswordToken = resetPasswordToken
	}
}

func AccountWithPaginationURL(paginationURL string) AccountFilterOption {
	return func(q *AccountFilter) {
		q.PaginationURL = paginationURL
	}
}

func AccountWithLimit(limit int64) AccountFilterOption {
	return func(q *AccountFilter) {
		q.Limit = limit
	}
}

func AccountWithPage(page int64) AccountFilterOption {
	return func(q *AccountFilter) {
		q.Page = page
	}
}

func AccountWithUrlValues(urlValues url.Values) AccountFilterOption {
	return func(q *AccountFilter) {
		q.UrlValues = urlValues
	}
}

type NewAdmin struct {
	*NewAccount
	AdminLevel uint8 `json:"admin_level"`
}

func (q *NewAdmin) Validate() error {
	if err := q.NewAccount.Validate(); err != nil {
		return err
	}
	if q.AdminLevel != AdminLevelSuperAdmin &&
		q.AdminLevel != AdminLevelAdmin {
		return fmt.Errorf("admin_level: should be either %d (super admin) / %d (admin)", AdminLevelSuperAdmin, AdminLevelAdmin)
	}
	return nil
}

type NewUser struct {
	*NewAccount
	CompanyID uint64 `json:"company_id,string"`
	UserLevel uint8  `json:"user_level"`
}

func (q *NewUser) Validate() error {
	if err := q.NewAccount.Validate(); err != nil {
		return err
	}
	if q.CompanyID == 0 {
		return errors.New("company_id: is required")
	}
	if q.UserLevel != UserLevelOwner && q.UserLevel != UserLevelStaff {
		return fmt.Errorf("user_level: should be either %d (owner) / %d (staff)", UserLevelOwner, UserLevelStaff)
	}
	return nil
}

type AccountDeactivation struct {
	Reason string `json:"reason"`
}

func (q *AccountDeactivation) Validate() error {
	if q.Reason = strings.TrimSpace(q.Reason); q.Reason == "" {
		return errors.New("reason: is required")
	}
	return nil
}

type LoginRequest struct {
	Login          string `json:"login" form:"login"`
	Base64Password string `json:"password" form:"password"`
	Password       string `json:"-" form:"-"`
}

func (q *LoginRequest) Validate() error {
	if q.Login = strings.TrimSpace(q.Login); q.Login == "" {
		return errors.New("login: is required")
	}
	if q.Base64Password = strings.TrimSpace(q.Base64Password); q.Base64Password == "" {
		return errors.New("password: is required")
	}
	password, err := helper.Base64Decode(q.Base64Password)
	if err != nil {
		return fmt.Errorf("password: %s", err.Error())
	}
	q.Password = password
	return nil
}

type LoginResponse struct {
	IDToken   string    `json:"id_token"`
	ExpiredAt time.Time `json:"expired_at"`
	Account   *Account  `json:"-"`
}

type AdminLoginResponse struct {
	IDToken   string    `json:"id_token"`
	ExpiredAt time.Time `json:"expired_at"`
	Account   *Admin    `json:"admin"`
}

type UserLoginResponse struct {
	IDToken   string    `json:"id_token"`
	ExpiredAt time.Time `json:"expired_at"`
	Account   *User     `json:"user"`
}

type Confirmation struct {
	Name           string  `json:"name"`
	Username       string  `json:"username"`
	Email          *string `json:"email"`
	Phone          *string `json:"phone"`
	Base64Password string  `json:"password"`
	Password       string  `json:"-"`
}

func (q *Confirmation) Validate() error {
	if q.Name = strings.TrimSpace(q.Name); q.Name == "" {
		return errors.New("name: is required")
	}
	if q.Username = strings.ToLower(strings.TrimSpace(q.Username)); q.Username == "" {
		return errors.New("username: is required")
	}
	q.Username = UsernameRegex.ReplaceAllString(q.Username, "")
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
			if PhoneNumberRegex.Find(helper.String2ByteSlice(*q.Phone)) == nil {
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

type ForgotPassword struct {
	Login string `json:"login"`
}

func (q *ForgotPassword) Validate() error {
	if q.Login = strings.TrimSpace(q.Login); q.Login == "" {
		return errors.New("login: is required")
	}
	return nil
}

type ResetPassword struct {
	Base64Password string `json:"password"`
	Password       string `json:"-"`
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

type ChangePassword struct {
	Base64OldPassword string `json:"old_password"`
	OldPassword       string `json:"-"`
	Base64NewPassword string `json:"new_password"`
	NewPassword       string `json:"-"`
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

type ChangeUsername struct {
	Base64Password string `json:"password"`
	Password       string `json:"-"`
	Username       string `json:"username"`
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
	q.Username = UsernameRegex.ReplaceAllString(q.Username, "")
	return nil
}

type ChangeEmail struct {
	Base64Password string `json:"password"`
	Password       string `json:"-"`
	Email          string `json:"email"`
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

type ChangePhone struct {
	Base64Password string `json:"password"`
	Password       string `json:"-"`
	Phone          string `json:"phone"`
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
	if q.Phone = strings.TrimSpace(q.Phone); q.Phone == "" {
		return errors.New("phone: is required")
	}
	phone, err := phonenumbers.Parse(q.Phone, "ID")
	if err != nil {
		return err
	}
	q.Phone = phonenumbers.Format(phone, phonenumbers.E164)
	if PhoneNumberRegex.Find(helper.String2ByteSlice(q.Phone)) == nil {
		return errors.New("phone: invalid number")
	}
	return nil
}

var ErrAccountNotFound = errors.New("account not found")
var ErrLoginFailed = customErrors.New(fiber.StatusBadRequest, "login failed")
var ErrUniqueUsernameViolation = errors.New("username: already exists")
var ErrUniqueEmailViolation = errors.New("email: already exists")
var ErrUniquePhoneViolation = errors.New("phone: already exists")
var ErrUniqueConfirmationTokenViolation = errors.New("confirmation_token: already exists")
var ErrUniqueEmailConfirmationTokenViolation = errors.New("email_confirmation_token: already exists")
var ErrUniquePhoneConfirmationTokenViolation = errors.New("phone_confirmation_token: already exists")
var ErrUniqueResetPasswordTokenViolation = errors.New("reset_password_token: already exists")
var ErrUniqueLoginUnlockTokenViolation = errors.New("login_unlock_token: already exists")
