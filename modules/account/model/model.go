package model

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/nyaruka/phonenumbers"
	customErrors "github.com/roysitumorang/sadia/errors"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
)

const (
	AdminLevelSuperAdmin uint8 = iota
	AdminLevelAdmin
)

const (
	UserLevelOwner uint8 = iota
	UserLevelStaff
)

type (
	Account struct {
		RowNo                   uint64     `json:"row_no,omitempty"`
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
		CreatedBy               *string    `json:"-"`
		CreatedAt               time.Time  `json:"created_at"`
		UpdatedAt               time.Time  `json:"updated_at"`
		DeactivatedBy           *string    `json:"-"`
		DeactivatedAt           *time.Time `json:"deactivated_at"`
		DeactivationReason      *string    `json:"-"`
	}

	Admin struct {
		*Account
		AdminLevel uint8 `json:"admin_level"`
	}

	User struct {
		*Account
		CompanyID        string  `json:"company_id"`
		UserLevel        uint8   `json:"user_level"`
		CurrentSessionID *string `json:"current_session_id"`
	}

	Filter struct {
		AccountIDs,
		CompanyIDs []string
		StatusList []int
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

	FilterOption func(q *Filter)

	NewAdmin struct {
		*models.NewAccount
		AdminLevel uint8 `json:"admin_level"`
	}

	NewUser struct {
		*models.NewAccount
		CompanyID string `json:"company_id"`
		UserLevel uint8  `json:"user_level"`
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
		Account   *Account  `json:"-"`
	}

	AdminLoginResponse struct {
		IDToken   string    `json:"id_token"`
		ExpiredAt time.Time `json:"expired_at"`
		Account   *Admin    `json:"admin"`
	}

	UserLoginResponse struct {
		IDToken   string    `json:"id_token"`
		ExpiredAt time.Time `json:"expired_at"`
		Account   *User     `json:"user"`
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
	filter := &Filter{UrlValues: url.Values{}}
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

func WithCompanyIDs(companyIDs ...string) FilterOption {
	return func(q *Filter) {
		q.CompanyIDs = companyIDs
	}
}

func WithStatusList(statusList ...int) FilterOption {
	return func(q *Filter) {
		q.StatusList = statusList
	}
}

func WithAccountTypes(accountTypes ...uint8) FilterOption {
	return func(q *Filter) {
		q.AccountTypes = accountTypes
	}
}

func WithAdminLevels(adminLevels ...uint8) FilterOption {
	return func(q *Filter) {
		q.AdminLevels = adminLevels
	}
}

func WithUserLevels(userLevels ...uint8) FilterOption {
	return func(q *Filter) {
		q.UserLevels = userLevels
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

func WithUsername(username string) FilterOption {
	return func(q *Filter) {
		q.Username = username
	}
}

func WithConfirmationToken(confirmationToken string) FilterOption {
	return func(q *Filter) {
		q.ConfirmationToken = confirmationToken
	}
}

func WithEmail(email string) FilterOption {
	return func(q *Filter) {
		q.Email = email
	}
}

func WithEmailConfirmationToken(emailConfirmationToken string) FilterOption {
	return func(q *Filter) {
		q.EmailConfirmationToken = emailConfirmationToken
	}
}

func WithPhone(phone string) FilterOption {
	return func(q *Filter) {
		q.Phone = phone
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

func WithUrlValues(urlValues url.Values) FilterOption {
	return func(q *Filter) {
		q.UrlValues = urlValues
	}
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

func (q *NewUser) Validate() error {
	if err := q.NewAccount.Validate(); err != nil {
		return err
	}
	if q.CompanyID = strings.TrimSpace(q.CompanyID); q.CompanyID == "" {
		return errors.New("company_id: is required")
	}
	if q.UserLevel != UserLevelOwner && q.UserLevel != UserLevelStaff {
		return fmt.Errorf("user_level: should be either %d (owner) / %d (staff)", UserLevelOwner, UserLevelStaff)
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

func (q *Confirmation) Validate() error {
	if q.Name = strings.TrimSpace(q.Name); q.Name == "" {
		return errors.New("name: is required")
	}
	if q.Username = strings.ToLower(strings.TrimSpace(q.Username)); q.Username == "" {
		return errors.New("username: is required")
	}
	q.Username = models.UsernameRegex.ReplaceAllString(q.Username, "")
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
			if models.PhoneNumberRegex.Find(helper.String2ByteSlice(*q.Phone)) == nil {
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
	q.Username = models.UsernameRegex.ReplaceAllString(q.Username, "")
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
	if q.Phone = strings.TrimSpace(q.Phone); q.Phone == "" {
		return errors.New("phone: is required")
	}
	phone, err := phonenumbers.Parse(q.Phone, "ID")
	if err != nil {
		return err
	}
	q.Phone = phonenumbers.Format(phone, phonenumbers.E164)
	if models.PhoneNumberRegex.Find(helper.String2ByteSlice(q.Phone)) == nil {
		return errors.New("phone: invalid number")
	}
	return nil
}
