package presenter

import (
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
	}
)

func New(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
) *accountHTTPHandler {
	return &accountHTTPHandler{
		jwtUseCase:     jwtUseCase,
		accountUseCase: accountUseCase,
	}
}

func (q *accountHTTPHandler) Mount(r fiber.Router) {
	adminKeyAuth := middleware.AdminKeyAuth(q.jwtUseCase, q.accountUseCase)
	superAdminKeyAuth := middleware.AdminKeyAuth(q.jwtUseCase, q.accountUseCase, accountModel.AdminLevelSuperAdmin)
	admin := r.Group("/admin")
	admin.Get("", adminKeyAuth, q.AdminFindAccounts).
		Post("", superAdminKeyAuth, q.AdminCreateAccount).
		Get("/:id", adminKeyAuth, q.AdminFindAccountByID).
		Delete("/:id", superAdminKeyAuth, q.AdminDeactivateAccount).
		Group("/me").
		Get("/about", adminKeyAuth, q.AdminProfile).
		Put("/password", adminKeyAuth, q.AdminChangePassword).
		Put("/username", adminKeyAuth, q.AdminChangeUsername).
		Put("/email", adminKeyAuth, q.AdminChangeEmail).
		Put("/phone", adminKeyAuth, q.AdminChangePhone)
	r.Post("/login", q.Login).
		Get("/confirmation/:token", q.FindAccountByConfirmationToken).
		Put("/confirmation/:token", q.ConfirmAccount).
		Get("/email/confirm/:token", q.ConfirmAccountEmail).
		Get("/phone/confirm/:token", q.ConfirmAccountPhone).
		Get("/unlock/:token", q.UnlockAccount).
		Put("/password/forgot", q.ForgotPassword).
		Get("/password/reset/:token", q.FindAccountByResetPasswordToken).
		Put("/password/reset/:token", q.ResetPassword)
	userKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase)
	ownerKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase, accountModel.UserLevelOwner)
	r.Get("", ownerKeyAuth, q.UserFindUsers).
		Post("", ownerKeyAuth, q.UserCreateUser).
		Get("/:id", ownerKeyAuth, q.UserFindUserByID).
		Delete("/:id", ownerKeyAuth, q.UserDeactivateUser).
		Group("/me").
		Get("", userKeyAuth, q.UserProfile).
		Put("/password", userKeyAuth, q.UserChangePassword).
		Put("/username", userKeyAuth, q.UserChangeUsername).
		Put("/email", userKeyAuth, q.UserChangeEmail).
		Put("/phone", userKeyAuth, q.UserChangePhone)
}

func (q *accountHTTPHandler) AdminFindAccounts(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminFindAccounts"
	filter, err := sanitizer.FindAccounts(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	rows, pagination, err := q.accountUseCase.FindAccounts(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *accountHTTPHandler) AdminCreateAccount(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminCreateAccount"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*accountModel.Admin)
	request, statusCode, err := sanitizer.ValidateAccount(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateAccount")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	request.CreatedBy = &currentAdmin.ID
	tx, err := helper.BeginTx(ctx)
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
	response, err := q.accountUseCase.CreateAccount(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *accountHTTPHandler) AdminFindAccountByID(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminFindAccountByID"
	accounts, _, err := q.accountUseCase.FindAccounts(ctx, accountModel.NewFilter(accountModel.WithLogin(c.Params("id")), accountModel.WithUrlValues(url.Values{})))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("account not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(accounts[0]).WriteResponse(c)
}

func (q *accountHTTPHandler) AdminDeactivateAccount(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminDeactivateAccount"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*accountModel.Admin)
	request, statusCode, err := sanitizer.ValidateDeactivation(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateDeactivation")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithLogin(c.Params("id")), accountModel.WithUrlValues(url.Values{})),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("account not found").WriteResponse(c)
	}
	account := accounts[0]
	if account.Status != models.StatusConfirmed {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("cannot deactivate unconfirmed & deactivated account").WriteResponse(c)
	}
	now := time.Now()
	account.Status = models.StatusDeactivated
	account.DeactivatedBy = &currentAdmin.ID
	account.DeactivatedAt = &now
	account.DeactivationReason = &request.Reason
	tx, err := helper.BeginTx(ctx)
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
	if _, err = q.jwtUseCase.DeleteJWTs(ctx, tx, jwtModel.NewDeleteFilter(jwtModel.WithAccountID(account.ID))); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(account).WriteResponse(c)
}

func (q *accountHTTPHandler) AdminProfile(c *fiber.Ctx) error {
	response := c.Locals(models.CurrentAdmin)
	return helper.NewResponse(fiber.StatusOK).SetData(response).WriteResponse(c)
}

func (q *accountHTTPHandler) AdminChangePassword(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminChangePassword"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*accountModel.Admin)
	request, statusCode, err := sanitizer.ValidateChangePassword(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateChangePassword")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	oldEncryptedPassword := helper.String2ByteSlice(*currentAdmin.EncryptedPassword)
	if !helper.MatchedHashAndPassword(oldEncryptedPassword, helper.String2ByteSlice(request.OldPassword)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("old_password: invalid").WriteResponse(c)
	}
	if helper.MatchedHashAndPassword(oldEncryptedPassword, helper.String2ByteSlice(request.NewPassword)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password reuse prohibited").WriteResponse(c)
	}
	now := time.Now()
	encryptedPassword, err := helper.HashPassword(request.NewPassword)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrHashPassword")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	currentAdmin.EncryptedPassword = encryptedPassword
	currentAdmin.LastPasswordChange = &now
	tx, err := helper.BeginTx(ctx)
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
	if err = q.accountUseCase.UpdateAdmin(ctx, tx, currentAdmin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) AdminChangeUsername(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminChangeUsername"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*accountModel.Admin)
	request, statusCode, err := sanitizer.ValidateChangeUsername(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateChangeUsername")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	if currentAdmin.Username == request.Username {
		return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*currentAdmin.EncryptedPassword)
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(request.Password)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password: invalid").WriteResponse(c)
	}
	now := time.Now()
	currentAdmin.Username = request.Username
	currentAdmin.UpdatedAt = now
	tx, err := helper.BeginTx(ctx)
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
	if err = q.accountUseCase.UpdateAdmin(ctx, tx, currentAdmin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) AdminChangeEmail(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminChangeEmail"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*accountModel.Admin)
	request, statusCode, err := sanitizer.ValidateChangeEmail(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateChangeEmail")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	if currentAdmin.Email != nil && *currentAdmin.Email == request.Email {
		return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*currentAdmin.EncryptedPassword)
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(request.Password)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password: invalid").WriteResponse(c)
	}
	now := time.Now()
	emailConfirmationToken := helper.RandomString(32)
	currentAdmin.UnconfirmedEmail = &request.Email
	currentAdmin.EmailConfirmationToken = &emailConfirmationToken
	currentAdmin.EmailConfirmationSentAt = &now
	tx, err := helper.BeginTx(ctx)
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
	if err = q.accountUseCase.UpdateAdmin(ctx, tx, currentAdmin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) AdminChangePhone(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminChangePhone"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*accountModel.Admin)
	request, statusCode, err := sanitizer.ValidateChangePhone(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateChangePhone")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	if currentAdmin.Phone != nil && *currentAdmin.Phone == request.Phone {
		return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*currentAdmin.EncryptedPassword)
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(request.Password)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password: invalid").WriteResponse(c)
	}
	now := time.Now()
	phoneConfirmationToken := helper.RandomNumber(6)
	currentAdmin.UnconfirmedPhone = &request.Phone
	currentAdmin.PhoneConfirmationToken = &phoneConfirmationToken
	currentAdmin.PhoneConfirmationSentAt = &now
	tx, err := helper.BeginTx(ctx)
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
	if err = q.accountUseCase.UpdateAdmin(ctx, tx, currentAdmin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
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
		accountModel.NewFilter(accountModel.WithLogin(request.Login), accountModel.WithUrlValues(url.Values{})),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 ||
		accounts[0].Status != models.StatusConfirmed ||
		accounts[0].EncryptedPassword == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	account := accounts[0]
	if account.LoginLockedAt != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login locked out, max. failed attempts exceeded").WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*account.EncryptedPassword)
	now := time.Now()
	tx, err := helper.BeginTx(ctx)
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
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(request.Password)) {
		if account.LoginFailedAttempts++; account.LoginFailedAttempts >= helper.GetLoginMaxFailedAttempts() {
			loginLockoutToken := helper.RandomString(32)
			account.LoginLockedAt = &now
			account.LoginUnlockToken = &loginLockoutToken
		}
		if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
			return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
		}
		if account.LoginLockedAt != nil {
			if _, err = q.jwtUseCase.DeleteJWTs(ctx, tx, jwtModel.NewDeleteFilter(jwtModel.WithAccountID(account.ID))); err != nil {
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
	jwt, err := q.jwtUseCase.CreateJWT(ctx, tx, account.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	tokenString, err := helper.GenerateAccessToken(account.ID, jwt.Token, account.Username, jwt.CreatedAt, jwt.ExpiredAt)
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

func (q *accountHTTPHandler) FindAccountByConfirmationToken(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-FindAccountByConfirmationToken"
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithConfirmationToken(c.Params("token")), accountModel.WithUrlValues(url.Values{})),
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
		accountModel.NewFilter(accountModel.WithConfirmationToken(c.Params("token")), accountModel.WithUrlValues(url.Values{})),
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
	account.Status = models.StatusConfirmed
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
	tx, err := helper.BeginTx(ctx)
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
	jwt, err := q.jwtUseCase.CreateJWT(ctx, tx, account.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	tokenString, err := helper.GenerateAccessToken(account.ID, jwt.Token, account.Username, jwt.CreatedAt, jwt.ExpiredAt)
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
		accountModel.NewFilter(accountModel.WithEmailConfirmationToken(c.Params("token")), accountModel.WithUrlValues(url.Values{})),
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
	tx, err := helper.BeginTx(ctx)
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
		accountModel.NewFilter(accountModel.WithPhoneConfirmationToken(c.Params("token")), accountModel.WithUrlValues(url.Values{})),
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
	tx, err := helper.BeginTx(ctx)
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
		accountModel.NewFilter(accountModel.WithLoginUnlockToken(c.Params("token")), accountModel.WithUrlValues(url.Values{})),
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
	tx, err := helper.BeginTx(ctx)
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
		accountModel.NewFilter(accountModel.WithLogin(request.Login), accountModel.WithUrlValues(url.Values{})),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("login not found").WriteResponse(c)
	}
	account := accounts[0]
	if account.Status != models.StatusConfirmed {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("cannot reset password for unconfirmed/deactivated account").WriteResponse(c)
	}
	if account.LoginLockedAt != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("cannot reset password for locked out account").WriteResponse(c)
	}
	now := time.Now()
	resetPasswordToken := helper.RandomString(32)
	account.ResetPasswordToken = &resetPasswordToken
	account.ResetPasswordSentAt = &now
	tx, err := helper.BeginTx(ctx)
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
		accountModel.NewFilter(accountModel.WithResetPasswordToken(c.Params("token")), accountModel.WithUrlValues(url.Values{})),
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
		accountModel.NewFilter(accountModel.WithResetPasswordToken(c.Params("token")), accountModel.WithUrlValues(url.Values{})),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	account := accounts[0]
	if account.EncryptedPassword != nil &&
		helper.MatchedHashAndPassword(
			helper.String2ByteSlice(*account.EncryptedPassword),
			helper.String2ByteSlice(request.Password),
		) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password reuse prohibited").WriteResponse(c)
	}
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
	tx, err := helper.BeginTx(ctx)
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
	jwt, err := q.jwtUseCase.CreateJWT(ctx, tx, account.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	tokenString, err := helper.GenerateAccessToken(account.ID, jwt.Token, account.Username, jwt.CreatedAt, jwt.ExpiredAt)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
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

func (q *accountHTTPHandler) UserFindUsers(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserFindUsers"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	filter, err := sanitizer.FindAccounts(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	filter.CompanyIDs = []string{currentUser.CompanyID}
	rows, pagination, err := q.accountUseCase.FindUsers(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *accountHTTPHandler) UserCreateUser(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserCreateUser"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	request, statusCode, err := sanitizer.ValidateUser(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateUser")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	request.CompanyID = currentUser.CompanyID
	request.CreatedBy = &currentUser.ID
	tx, err := helper.BeginTx(ctx)
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
	response, err := q.accountUseCase.CreateUser(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *accountHTTPHandler) UserFindUserByID(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserFindUserByID"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	users, _, err := q.accountUseCase.FindUsers(ctx, accountModel.NewFilter(accountModel.WithLogin(c.Params("id")), accountModel.WithCompanyIDs(currentUser.CompanyID), accountModel.WithUrlValues(url.Values{})))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("user not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(users[0]).WriteResponse(c)
}

func (q *accountHTTPHandler) UserDeactivateUser(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserDeactivateUser"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	request, statusCode, err := sanitizer.ValidateDeactivation(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateDeactivation")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	users, _, err := q.accountUseCase.FindUsers(
		ctx,
		accountModel.NewFilter(accountModel.WithLogin(c.Params("id")), accountModel.WithCompanyIDs(currentUser.CompanyID), accountModel.WithUrlValues(url.Values{})),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("user not found").WriteResponse(c)
	}
	user := users[0]
	if user.Status != models.StatusConfirmed {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("cannot deactivate unconfirmed & deactivated user").WriteResponse(c)
	}
	now := time.Now()
	user.Status = models.StatusDeactivated
	user.DeactivatedBy = &currentUser.ID
	user.DeactivatedAt = &now
	user.DeactivationReason = &request.Reason
	tx, err := helper.BeginTx(ctx)
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
	if err = q.accountUseCase.UpdateUser(ctx, tx, user); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if _, err = q.jwtUseCase.DeleteJWTs(ctx, tx, jwtModel.NewDeleteFilter(jwtModel.WithAccountID(user.ID))); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(user).WriteResponse(c)
}

func (q *accountHTTPHandler) UserProfile(c *fiber.Ctx) error {
	response := c.Locals(models.CurrentUser)
	return helper.NewResponse(fiber.StatusOK).SetData(response).WriteResponse(c)
}

func (q *accountHTTPHandler) UserChangePassword(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserChangePassword"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	request, statusCode, err := sanitizer.ValidateChangePassword(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateChangePassword")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	oldEncryptedPassword := helper.String2ByteSlice(*currentUser.EncryptedPassword)
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
	currentUser.EncryptedPassword = encryptedPassword
	currentUser.LastPasswordChange = &now
	tx, err := helper.BeginTx(ctx)
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
	if err = q.accountUseCase.UpdateUser(ctx, tx, currentUser); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) UserChangeUsername(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserChangeUsername"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	request, statusCode, err := sanitizer.ValidateChangeUsername(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateChangeUsername")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	if currentUser.Username == request.Username {
		return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*currentUser.EncryptedPassword)
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(request.Password)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password: invalid").WriteResponse(c)
	}
	now := time.Now()
	currentUser.Username = request.Username
	currentUser.UpdatedAt = now
	tx, err := helper.BeginTx(ctx)
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
	if err = q.accountUseCase.UpdateUser(ctx, tx, currentUser); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) UserChangeEmail(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserChangeEmail"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	request, statusCode, err := sanitizer.ValidateChangeEmail(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateChangeEmail")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	if currentUser.Email != nil && *currentUser.Email == request.Email {
		return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*currentUser.EncryptedPassword)
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(request.Password)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password: invalid").WriteResponse(c)
	}
	now := time.Now()
	emailConfirmationToken := helper.RandomString(32)
	currentUser.UnconfirmedEmail = &request.Email
	currentUser.EmailConfirmationToken = &emailConfirmationToken
	currentUser.EmailConfirmationSentAt = &now
	tx, err := helper.BeginTx(ctx)
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
	if err = q.accountUseCase.UpdateUser(ctx, tx, currentUser); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) UserChangePhone(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserChangePhone"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	request, statusCode, err := sanitizer.ValidateChangePhone(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateChangePhone")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	if currentUser.Phone != nil && *currentUser.Phone == request.Phone {
		return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*currentUser.EncryptedPassword)
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(request.Password)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password: invalid").WriteResponse(c)
	}
	now := time.Now()
	phoneConfirmationToken := helper.RandomNumber(6)
	currentUser.UnconfirmedPhone = &request.Phone
	currentUser.PhoneConfirmationToken = &phoneConfirmationToken
	currentUser.PhoneConfirmationSentAt = &now
	tx, err := helper.BeginTx(ctx)
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
	if err = q.accountUseCase.UpdateUser(ctx, tx, currentUser); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}
