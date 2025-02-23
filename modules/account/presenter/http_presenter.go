package presenter

import (
	"crypto/rsa"
	"errors"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	"github.com/roysitumorang/sadia/modules/account/sanitizer"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	jwtModel "github.com/roysitumorang/sadia/modules/jwt/model"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	"go.uber.org/zap"
)

type (
	accountHTTPHandler struct {
		jwtUseCase     jwtUseCase.JwtUseCase
		accountUseCase accountUseCase.AccountUseCase
		privateKey     *rsa.PrivateKey
		accessTokenAge time.Duration
	}
)

func New(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	privateKey *rsa.PrivateKey,
	accessTokenAge time.Duration,
) *accountHTTPHandler {
	return &accountHTTPHandler{
		jwtUseCase:     jwtUseCase,
		accountUseCase: accountUseCase,
		privateKey:     privateKey,
		accessTokenAge: accessTokenAge,
	}
}

func (q *accountHTTPHandler) Mount(r fiber.Router) {
	r.Group("/admin", middleware.KeyAuth(q.jwtUseCase, q.accountUseCase, accountModel.AccountTypeAdmin)).
		Get("", q.FindAccounts).
		Post("", q.CreateAccount).
		Get("/:id", q.FindAccountByID).
		Delete("/:id", q.DeactivateAccount)
	r.Post("/login", q.Login).
		Get("/confirmation/:token", q.FindAccountByConfirmationToken).
		Put("/confirmation/:token", q.ConfirmAccount).
		Get("/email/confirm/:token", q.ConfirmAccountEmail).
		Get("/phone/confirm/:token", q.ConfirmAccountPhone).
		Get("/unlock/:token", q.UnlockAccount).
		Put("/password/forgot", q.ForgotPassword).
		Get("/password/reset/:token", q.FindAccountByResetPasswordToken).
		Put("/password/reset/:token", q.ResetPassword)
	r.Group("/me", middleware.KeyAuth(q.jwtUseCase, q.accountUseCase)).
		Get("", q.Me).
		Put("/password", q.ChangePassword).
		Put("/username", q.ChangeUsername).
		Put("/email", q.ChangeEmail).
		Put("/phone", q.ChangePhone)
}

func (q *accountHTTPHandler) FindAccounts(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-FindAccounts"
	filter, urlValues, err := sanitizer.FindAccounts(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	rows, pagination, err := q.accountUseCase.FindAccounts(
		ctx,
		filter,
		urlValues,
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]interface{}{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *accountHTTPHandler) CreateAccount(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-CreateAccount"
	currentAccount, _ := c.Locals(models.CurrentAccount).(*accountModel.Account)
	request, statusCode, err := sanitizer.ValidateAccount(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateAccount")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	request.CreatedBy = &currentAccount.ID
	response, err := q.accountUseCase.CreateAccount(ctx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateAccount")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *accountHTTPHandler) FindAccountByID(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-FindAccountByID"
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithLogin(c.Params("id"))),
		url.Values{},
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("account not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(accounts[0]).WriteResponse(c)
}

func (q *accountHTTPHandler) DeactivateAccount(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-DeactivateAccount"
	currentAccount, _ := c.Locals(models.CurrentAccount).(*accountModel.Account)
	request, statusCode, err := sanitizer.ValidateDeactivation(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateDeactivation")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithLogin(c.Params("id"))),
		url.Values{},
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("account not found").WriteResponse(c)
	}
	account := accounts[0]
	if account.Status != accountModel.StatusActive {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("cannot deactivate unconfirmed & deactivated account").WriteResponse(c)
	}
	now := time.Now()
	account.Status = accountModel.StatusDeactivated
	account.DeactivatedBy = &currentAccount.ID
	account.DeactivatedAt = &now
	account.DeactivationReason = &request.Reason
	tx, err := q.accountUseCase.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	defer func() {
		errRollback := tx.Rollback(ctx)
		if errors.Is(errRollback, pgx.ErrTxClosed) {
			errRollback = nil
		}
		if errRollback != nil {
			helper.Log(ctx, zap.ErrorLevel, errRollback.Error(), ctxt, "ErrRollback")
		}
	}()
	if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if _, err = q.jwtUseCase.DeleteJWTs(ctx, tx, time.Time{}, account.ID); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(account).WriteResponse(c)
}

func (q *accountHTTPHandler) Login(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-Login"
	request, statusCode, err := sanitizer.ValidateLogin(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateLogin")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithLogin(request.Login)),
		url.Values{},
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 ||
		accounts[0].Status != accountModel.StatusActive ||
		accounts[0].EncryptedPassword == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	account := accounts[0]
	if account.LoginLockedAt != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login locked out, max. failed attempts exceeded").WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*account.EncryptedPassword)
	password, err := request.DecodePassword()
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDecodePassword")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	now := time.Now()
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(password)) {
		account.LoginFailedAttempts++
		tx, err := q.accountUseCase.BeginTx(ctx)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
			return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
		}
		defer func() {
			errRollback := tx.Rollback(ctx)
			if errors.Is(errRollback, pgx.ErrTxClosed) {
				errRollback = nil
			}
			if errRollback != nil {
				helper.Log(ctx, zap.ErrorLevel, errRollback.Error(), ctxt, "ErrRollback")
			}
		}()
		if account.LoginFailedAttempts >= helper.GetLoginMaxFailedAttempts() {
			loginLockoutToken := helper.RandomString(32)
			account.LoginLockedAt = &now
			account.LoginUnlockToken = &loginLockoutToken
		}
		if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
			return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
		}
		if account.LoginLockedAt != nil {
			if _, err = q.jwtUseCase.DeleteJWTs(ctx, tx, time.Time{}, account.ID); err != nil {
				helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
				return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
			}
		}
		if err = tx.Commit(ctx); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
			return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
		}
		if account.LoginLockedAt != nil {
			return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login locked out, max. failed attempts exceeded").WriteResponse(c)
		}
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	_, jwtID, jwtToken, err := helper.GenerateUniqueID()
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateUniqueID")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	jwt := jwtModel.JsonWebToken{
		ID:        jwtID,
		Token:     jwtToken,
		AccountID: account.ID,
		CreatedAt: now,
		ExpiredAt: now.Add(q.accessTokenAge),
	}
	tokenString, err := helper.GenerateAccessToken(account.ID, jwtToken, account.Username, jwt.CreatedAt, jwt.ExpiredAt, q.privateKey)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	ipAddress := c.IP()
	account.LoginCount++
	account.LastLoginAt = account.CurrentLoginAt
	account.LastLoginIP = account.CurrentLoginIP
	account.CurrentLoginAt = &now
	account.CurrentLoginIP = &ipAddress
	account.LoginFailedAttempts = 0
	tx, err := q.accountUseCase.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	defer func() {
		errRollback := tx.Rollback(ctx)
		if errors.Is(errRollback, pgx.ErrTxClosed) {
			errRollback = nil
		}
		if errRollback != nil {
			helper.Log(ctx, zap.ErrorLevel, errRollback.Error(), ctxt, "ErrRollback")
		}
	}()
	if err = q.jwtUseCase.CreateJWT(ctx, tx, jwt); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response := accountModel.LoginResponse{
		IDToken:   tokenString,
		ExpiredAt: jwt.ExpiredAt,
		Account:   account,
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *accountHTTPHandler) Me(c *fiber.Ctx) error {
	response := c.Locals(models.CurrentAccount)
	return helper.NewResponse(fiber.StatusOK).SetData(response).WriteResponse(c)
}

func (q *accountHTTPHandler) FindAccountByConfirmationToken(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-FindAccountByConfirmationToken"
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithConfirmationToken(c.Params("token"))),
		url.Values{},
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("account not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(accounts[0]).WriteResponse(c)
}

func (q *accountHTTPHandler) ConfirmAccount(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-ConfirmAccount"
	request, statusCode, err := sanitizer.ValidateConfirmation(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateConfirmation")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithConfirmationToken(c.Params("token"))),
		url.Values{},
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	now := time.Now()
	account := accounts[0]
	account.Status = accountModel.StatusActive
	account.Name = request.Name
	account.Username = request.Username
	account.ConfirmationToken = nil
	account.ConfirmedAt = &now
	emailConfirmationToken, phoneConfirmationToken := helper.RandomString(32), helper.RandomNumber(6)
	if request.Email != nil &&
		(account.UnconfirmedEmail == nil ||
			*account.UnconfirmedEmail != *request.Email) {
		account.UnconfirmedEmail = request.Email
		account.EmailConfirmationToken = &emailConfirmationToken
		account.EmailConfirmationSentAt = &now
	}
	if request.Phone != nil &&
		(account.UnconfirmedPhone == nil ||
			*account.UnconfirmedPhone != *request.Phone) {
		account.UnconfirmedPhone = request.Phone
		account.PhoneConfirmationToken = &phoneConfirmationToken
		account.PhoneConfirmationSentAt = &now
	}
	encryptedPassword, err := helper.HashPassword(request.Password)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrHashPassword")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	account.EncryptedPassword = encryptedPassword
	account.LastPasswordChange = &now
	_, jwtID, jwtToken, err := helper.GenerateUniqueID()
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateUniqueID")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	jwt := jwtModel.JsonWebToken{
		ID:        jwtID,
		Token:     jwtToken,
		AccountID: account.ID,
		CreatedAt: now,
		ExpiredAt: now.Add(q.accessTokenAge),
	}
	tokenString, err := helper.GenerateAccessToken(account.ID, jwtToken, account.Username, jwt.CreatedAt, jwt.ExpiredAt, q.privateKey)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	ipAddress := c.IP()
	account.LoginCount++
	account.LastLoginAt = account.CurrentLoginAt
	account.LastLoginIP = account.CurrentLoginIP
	account.CurrentLoginAt = &now
	account.CurrentLoginIP = &ipAddress
	tx, err := q.accountUseCase.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	defer func() {
		errRollback := tx.Rollback(ctx)
		if errors.Is(errRollback, pgx.ErrTxClosed) {
			errRollback = nil
		}
		if errRollback != nil {
			helper.Log(ctx, zap.ErrorLevel, errRollback.Error(), ctxt, "ErrRollback")
		}
	}()
	if err = q.jwtUseCase.CreateJWT(ctx, tx, jwt); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response := accountModel.LoginResponse{
		IDToken:   tokenString,
		ExpiredAt: jwt.ExpiredAt,
		Account:   account,
	}
	return helper.NewResponse(fiber.StatusOK).SetData(response).WriteResponse(c)
}

func (q *accountHTTPHandler) ConfirmAccountEmail(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-ConfirmAccountEmail"
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithEmailConfirmationToken(c.Params("token"))),
		url.Values{},
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	now := time.Now()
	account := accounts[0]
	email := *account.UnconfirmedEmail
	account.Email = &email
	account.UnconfirmedEmail = nil
	account.EmailConfirmationToken = nil
	account.EmailConfirmationSentAt = nil
	account.EmailConfirmedAt = &now
	tx, err := q.accountUseCase.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	defer func() {
		errRollback := tx.Rollback(ctx)
		if errors.Is(errRollback, pgx.ErrTxClosed) {
			errRollback = nil
		}
		if errRollback != nil {
			helper.Log(ctx, zap.ErrorLevel, errRollback.Error(), ctxt, "ErrRollback")
		}
	}()
	if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) ConfirmAccountPhone(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-ConfirmAccountPhone"
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithPhoneConfirmationToken(c.Params("token"))),
		url.Values{},
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	now := time.Now()
	account := accounts[0]
	phone := *account.UnconfirmedPhone
	account.Phone = &phone
	account.UnconfirmedPhone = nil
	account.PhoneConfirmationToken = nil
	account.PhoneConfirmationSentAt = nil
	account.PhoneConfirmedAt = &now
	tx, err := q.accountUseCase.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	defer func() {
		errRollback := tx.Rollback(ctx)
		if errors.Is(errRollback, pgx.ErrTxClosed) {
			errRollback = nil
		}
		if errRollback != nil {
			helper.Log(ctx, zap.ErrorLevel, errRollback.Error(), ctxt, "ErrRollback")
		}
	}()
	if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) UnlockAccount(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UnlockAccount"
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithLoginUnlockToken(c.Params("token"))),
		url.Values{},
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	account := accounts[0]
	account.LoginFailedAttempts = 0
	account.LoginLockedAt = nil
	account.LoginUnlockToken = nil
	tx, err := q.accountUseCase.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	defer func() {
		errRollback := tx.Rollback(ctx)
		if errors.Is(errRollback, pgx.ErrTxClosed) {
			errRollback = nil
		}
		if errRollback != nil {
			helper.Log(ctx, zap.ErrorLevel, errRollback.Error(), ctxt, "ErrRollback")
		}
	}()
	if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) ForgotPassword(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-ForgotPassword"
	request, statusCode, err := sanitizer.ValidateForgotPassword(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateForgotPassword")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithLogin(request.Login)),
		url.Values{},
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("login not found").WriteResponse(c)
	}
	account := accounts[0]
	if account.Status != accountModel.StatusActive {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("cannot reset password for unconfirmed/deactivated account").WriteResponse(c)
	}
	if account.LoginLockedAt != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("cannot reset password for locked out account").WriteResponse(c)
	}
	now := time.Now()
	resetPasswordToken := helper.RandomString(32)
	account.ResetPasswordToken = &resetPasswordToken
	account.ResetPasswordSentAt = &now
	tx, err := q.accountUseCase.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	defer func() {
		errRollback := tx.Rollback(ctx)
		if errors.Is(errRollback, pgx.ErrTxClosed) {
			errRollback = nil
		}
		if errRollback != nil {
			helper.Log(ctx, zap.ErrorLevel, errRollback.Error(), ctxt, "ErrRollback")
		}
	}()
	if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) FindAccountByResetPasswordToken(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-FindAccountByResetPasswordToken"
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithResetPasswordToken(c.Params("token"))),
		url.Values{},
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("account not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(accounts[0]).WriteResponse(c)
}

func (q *accountHTTPHandler) ResetPassword(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-ResetPassword"
	request, statusCode, err := sanitizer.ValidateResetPassword(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateResetPassword")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithResetPasswordToken(c.Params("token"))),
		url.Values{},
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	account := accounts[0]
	now := time.Now()
	account.ResetPasswordToken = nil
	account.ResetPasswordSentAt = nil
	encryptedPassword, err := helper.HashPassword(request.Password)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrHashPassword")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	account.EncryptedPassword = encryptedPassword
	account.LastPasswordChange = &now
	_, jwtID, jwtToken, err := helper.GenerateUniqueID()
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateUniqueID")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	jwt := jwtModel.JsonWebToken{
		ID:        jwtID,
		Token:     jwtToken,
		AccountID: account.ID,
		CreatedAt: now,
		ExpiredAt: now.Add(q.accessTokenAge),
	}
	tokenString, err := helper.GenerateAccessToken(account.ID, jwtToken, account.Username, jwt.CreatedAt, jwt.ExpiredAt, q.privateKey)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	tx, err := q.accountUseCase.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	defer func() {
		errRollback := tx.Rollback(ctx)
		if errors.Is(errRollback, pgx.ErrTxClosed) {
			errRollback = nil
		}
		if errRollback != nil {
			helper.Log(ctx, zap.ErrorLevel, errRollback.Error(), ctxt, "ErrRollback")
		}
	}()
	if err = q.jwtUseCase.CreateJWT(ctx, tx, jwt); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response := accountModel.LoginResponse{
		IDToken:   tokenString,
		ExpiredAt: jwt.ExpiredAt,
		Account:   account,
	}
	return helper.NewResponse(fiber.StatusOK).SetData(response).WriteResponse(c)
}

func (q *accountHTTPHandler) ChangePassword(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-ChangePassword"
	account, _ := c.Locals(models.CurrentAccount).(*accountModel.Account)
	request, statusCode, err := sanitizer.ValidateChangePassword(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateChangePassword")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	oldEncryptedPassword := helper.String2ByteSlice(*account.EncryptedPassword)
	if !helper.MatchedHashAndPassword(oldEncryptedPassword, helper.String2ByteSlice(request.OldPassword)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("old_password: invalid").WriteResponse(c)
	}
	if !helper.MatchedHashAndPassword(oldEncryptedPassword, helper.String2ByteSlice(request.NewPassword)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password reuse prohibited").WriteResponse(c)
	}
	now := time.Now()
	encryptedPassword, err := helper.HashPassword(request.NewPassword)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrHashPassword")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	account.EncryptedPassword = encryptedPassword
	account.LastPasswordChange = &now
	tx, err := q.accountUseCase.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	defer func() {
		errRollback := tx.Rollback(ctx)
		if errors.Is(errRollback, pgx.ErrTxClosed) {
			errRollback = nil
		}
		if errRollback != nil {
			helper.Log(ctx, zap.ErrorLevel, errRollback.Error(), ctxt, "ErrRollback")
		}
	}()
	if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) ChangeUsername(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-ChangeUsername"
	account, _ := c.Locals(models.CurrentAccount).(*accountModel.Account)
	request, statusCode, err := sanitizer.ValidateChangeUsername(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateChangeUsername")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	if account.Username == request.Username {
		return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*account.EncryptedPassword)
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(request.Password)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password: invalid").WriteResponse(c)
	}
	now := time.Now()
	account.Username = request.Username
	account.UpdatedAt = now
	tx, err := q.accountUseCase.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	defer func() {
		errRollback := tx.Rollback(ctx)
		if errors.Is(errRollback, pgx.ErrTxClosed) {
			errRollback = nil
		}
		if errRollback != nil {
			helper.Log(ctx, zap.ErrorLevel, errRollback.Error(), ctxt, "ErrRollback")
		}
	}()
	if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) ChangeEmail(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-ChangeEmail"
	account, _ := c.Locals(models.CurrentAccount).(*accountModel.Account)
	request, statusCode, err := sanitizer.ValidateChangeEmail(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateChangeEmail")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	if account.Email != nil && *account.Email == request.Email {
		return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*account.EncryptedPassword)
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(request.Password)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password: invalid").WriteResponse(c)
	}
	now := time.Now()
	emailConfirmationToken := helper.RandomString(32)
	account.UnconfirmedEmail = &request.Email
	account.EmailConfirmationToken = &emailConfirmationToken
	account.EmailConfirmationSentAt = &now
	tx, err := q.accountUseCase.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	defer func() {
		errRollback := tx.Rollback(ctx)
		if errors.Is(errRollback, pgx.ErrTxClosed) {
			errRollback = nil
		}
		if errRollback != nil {
			helper.Log(ctx, zap.ErrorLevel, errRollback.Error(), ctxt, "ErrRollback")
		}
	}()
	if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) ChangePhone(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-ChangePhone"
	account, _ := c.Locals(models.CurrentAccount).(*accountModel.Account)
	request, statusCode, err := sanitizer.ValidateChangePhone(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateChangePhone")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	if account.Phone != nil && *account.Phone == request.Phone {
		return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*account.EncryptedPassword)
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(request.Password)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password: invalid").WriteResponse(c)
	}
	now := time.Now()
	phoneConfirmationToken := helper.RandomNumber(6)
	account.UnconfirmedPhone = &request.Phone
	account.PhoneConfirmationToken = &phoneConfirmationToken
	account.PhoneConfirmationSentAt = &now
	tx, err := q.accountUseCase.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	defer func() {
		errRollback := tx.Rollback(ctx)
		if errors.Is(errRollback, pgx.ErrTxClosed) {
			errRollback = nil
		}
		if errRollback != nil {
			helper.Log(ctx, zap.ErrorLevel, errRollback.Error(), ctxt, "ErrRollback")
		}
	}()
	if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}
