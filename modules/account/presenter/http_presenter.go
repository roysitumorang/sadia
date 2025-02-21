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
		Get("/:uid", q.FindAccountByUID).
		Delete("/:uid", q.DeactivateAccount)
	r.Post("/login", q.Login).
		Get("/confirmation/:token", q.FindAccountByConfirmationToken).
		Put("/confirmation/:token", q.ConfirmAccount).
		Get("/email/confirm/:token", q.ConfirmAccountEmail).
		Get("/phone/confirm/:token", q.ConfirmAccountPhone)
	r.Get("/me", middleware.KeyAuth(q.jwtUseCase, q.accountUseCase), q.Me)
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
	request.CreatedBy = &currentAccount.UID
	response, err := q.accountUseCase.CreateAccount(ctx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateAccount")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *accountHTTPHandler) FindAccountByUID(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-FindAccountByUID"
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithLogin(c.Params("uid"))),
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
		accountModel.NewFilter(accountModel.WithLogin(c.Params("uid"))),
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
	account.DeactivatedBy = &currentAccount.UID
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
	if _, err = q.jwtUseCase.DeleteJWTs(ctx, tx, time.Time{}, account.UID); err != nil {
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
			account.LoginFailedAttempts = 0
			account.LoginLockedAt = &now
			account.LoginUnlockToken = &loginLockoutToken
		}
		if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
			return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
		}
		if account.LoginLockedAt != nil {
			if _, err = q.jwtUseCase.DeleteJWTs(ctx, tx, time.Time{}, account.UID); err != nil {
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
	jwtID, jwtUID, jwtToken, err := helper.GenerateUniqueID()
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateUniqueID")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	jwt := jwtModel.JsonWebToken{
		ID:         jwtID,
		UID:        jwtUID,
		Token:      jwtToken,
		AccountUID: account.UID,
		CreatedAt:  now,
		ExpiredAt:  now.Add(q.accessTokenAge),
	}
	tokenString, err := helper.GenerateAccessToken(account.UID, jwtToken, account.Username, jwt.CreatedAt, jwt.ExpiredAt, q.privateKey)
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
	jwtID, jwtUID, jwtToken, err := helper.GenerateUniqueID()
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateUniqueID")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	jwt := jwtModel.JsonWebToken{
		ID:         jwtID,
		UID:        jwtUID,
		Token:      jwtToken,
		AccountUID: account.UID,
		CreatedAt:  now,
		ExpiredAt:  now.Add(q.accessTokenAge),
	}
	tokenString, err := helper.GenerateAccessToken(account.UID, jwtToken, account.Username, jwt.CreatedAt, jwt.ExpiredAt, q.privateKey)
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
