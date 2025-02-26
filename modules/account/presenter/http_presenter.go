package presenter

import (
	"errors"
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
	r.Group("/admin").
		Get("/confirmation/:token", q.AdminFindAdminByConfirmationToken).
		Put("/confirmation/:token", q.AdminConfirmAccount).
		Get("/email/confirm/:token", q.AdminConfirmEmail).
		Get("/phone/confirm/:token", q.AdminConfirmPhone).
		Get("/unlock/:token", q.AdminUnlockAccount).
		Put("/password/forgot", q.AdminForgotPassword).
		Get("/password/reset/:token", q.AdminFindAdminByResetPasswordToken).
		Put("/password/reset/:token", q.AdminResetPassword).
		Post("/login", q.AdminLogin).
		Get("", adminKeyAuth, q.AdminFindAccounts).
		Post("", superAdminKeyAuth, q.AdminCreateAccount).
		Get("/:id", adminKeyAuth, q.AdminFindAccountByID).
		Delete("/:id", superAdminKeyAuth, q.AdminDeactivateAccount).
		Group("/me").
		Get("/about", adminKeyAuth, q.AdminProfile).
		Put("/password", adminKeyAuth, q.AdminChangePassword).
		Put("/username", adminKeyAuth, q.AdminChangeUsername).
		Put("/email", adminKeyAuth, q.AdminChangeEmail).
		Put("/phone", adminKeyAuth, q.AdminChangePhone)
	userKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase)
	ownerKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase, accountModel.UserLevelOwner)
	r.Get("/confirmation/:token", q.UserFindUserByConfirmationToken).
		Put("/confirmation/:token", q.UserConfirmAccount).
		Get("/email/confirm/:token", q.UserConfirmEmail).
		Get("/phone/confirm/:token", q.UserConfirmPhone).
		Get("/unlock/:token", q.UserUnlockAccount).
		Put("/password/forgot", q.UserForgotPassword).
		Get("/password/reset/:token", q.UserFindUserByResetPasswordToken).
		Put("/password/reset/:token", q.UserResetPassword).
		Post("/login", q.UserLogin).
		Get("", ownerKeyAuth, q.UserFindUsers).
		Post("", ownerKeyAuth, q.UserCreateUser).
		Get("/:id", ownerKeyAuth, q.UserFindUserByID).
		Delete("/:id", ownerKeyAuth, q.UserDeactivateUser).
		Group("/me").
		Get("/about", userKeyAuth, q.UserProfile).
		Put("/password", userKeyAuth, q.UserChangePassword).
		Put("/username", userKeyAuth, q.UserChangeUsername).
		Put("/email", userKeyAuth, q.UserChangeEmail).
		Put("/phone", userKeyAuth, q.UserChangePhone)
}

func (q *accountHTTPHandler) AdminFindAdminByConfirmationToken(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminFindAdminByConfirmationToken"
	admins, _, err := q.accountUseCase.FindAdmins(
		ctx,
		accountModel.NewFilter(accountModel.WithConfirmationToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAdmins")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(admins) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("admin not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(admins[0]).WriteResponse(c)
}

func (q *accountHTTPHandler) AdminConfirmAccount(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminConfirmAccount"
	request, statusCode, err := sanitizer.ValidateConfirmation(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateConfirmation")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	admins, _, err := q.accountUseCase.FindAdmins(
		ctx,
		accountModel.NewFilter(accountModel.WithConfirmationToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAdmins")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(admins) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	now := time.Now()
	admin := admins[0]
	admin.Status = models.StatusConfirmed
	admin.Name = request.Name
	admin.Username = request.Username
	admin.ConfirmationToken = nil
	admin.ConfirmedAt = &now
	emailConfirmationToken, phoneConfirmationToken := helper.RandomString(32), helper.RandomNumber(6)
	if request.Email != nil &&
		(admin.UnconfirmedEmail == nil ||
			*admin.UnconfirmedEmail != *request.Email) {
		admin.UnconfirmedEmail = request.Email
		admin.EmailConfirmationToken = &emailConfirmationToken
		admin.EmailConfirmationSentAt = &now
	}
	if request.Phone != nil &&
		(admin.UnconfirmedPhone == nil ||
			*admin.UnconfirmedPhone != *request.Phone) {
		admin.UnconfirmedPhone = request.Phone
		admin.PhoneConfirmationToken = &phoneConfirmationToken
		admin.PhoneConfirmationSentAt = &now
	}
	encryptedPassword, err := helper.HashPassword(request.Password)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrHashPassword")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	admin.EncryptedPassword = encryptedPassword
	admin.LastPasswordChange = &now
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
	jwt, err := q.jwtUseCase.CreateJWT(ctx, tx, admin.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	tokenString, err := helper.GenerateAccessToken(admin.ID, jwt.Token, admin.Username, jwt.CreatedAt, jwt.ExpiredAt)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	ipAddress := c.IP()
	admin.LoginCount++
	admin.LastLoginAt = admin.CurrentLoginAt
	admin.LastLoginIP = admin.CurrentLoginIP
	admin.CurrentLoginAt = &now
	admin.CurrentLoginIP = &ipAddress
	if err = q.accountUseCase.UpdateAdmin(ctx, tx, admin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response := accountModel.AdminLoginResponse{
		LoginResponse: accountModel.LoginResponse{
			IDToken:   tokenString,
			ExpiredAt: jwt.ExpiredAt,
		},
		Account: admin,
	}
	return helper.NewResponse(fiber.StatusOK).SetData(response).WriteResponse(c)
}

func (q *accountHTTPHandler) AdminConfirmEmail(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminConfirmEmail"
	admins, _, err := q.accountUseCase.FindAdmins(
		ctx,
		accountModel.NewFilter(accountModel.WithEmailConfirmationToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAdmins")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(admins) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	now := time.Now()
	admin := admins[0]
	email := *admin.UnconfirmedEmail
	admin.Email = &email
	admin.UnconfirmedEmail = nil
	admin.EmailConfirmationToken = nil
	admin.EmailConfirmationSentAt = nil
	admin.EmailConfirmedAt = &now
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
	if err = q.accountUseCase.UpdateAdmin(ctx, tx, admin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) AdminConfirmPhone(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminConfirmPhone"
	admins, _, err := q.accountUseCase.FindAdmins(
		ctx,
		accountModel.NewFilter(accountModel.WithPhoneConfirmationToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAdmins")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(admins) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	now := time.Now()
	admin := admins[0]
	phone := *admin.UnconfirmedPhone
	admin.Phone = &phone
	admin.UnconfirmedPhone = nil
	admin.PhoneConfirmationToken = nil
	admin.PhoneConfirmationSentAt = nil
	admin.PhoneConfirmedAt = &now
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
	if err = q.accountUseCase.UpdateAdmin(ctx, tx, admin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) AdminUnlockAccount(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminUnlockAccount"
	admins, _, err := q.accountUseCase.FindAdmins(
		ctx,
		accountModel.NewFilter(accountModel.WithLoginUnlockToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAdmins")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(admins) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	admin := admins[0]
	admin.LoginFailedAttempts = 0
	admin.LoginLockedAt = nil
	admin.LoginUnlockToken = nil
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
	if err = q.accountUseCase.UpdateAdmin(ctx, tx, admin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) AdminForgotPassword(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminForgotPassword"
	request, statusCode, err := sanitizer.ValidateForgotPassword(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateForgotPassword")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	admins, _, err := q.accountUseCase.FindAdmins(
		ctx,
		accountModel.NewFilter(accountModel.WithLogin(request.Login)),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAdmins")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(admins) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("login not found").WriteResponse(c)
	}
	admin := admins[0]
	if admin.Status != models.StatusConfirmed {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("cannot reset password for unconfirmed/deactivated account").WriteResponse(c)
	}
	if admin.LoginLockedAt != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("cannot reset password for locked out account").WriteResponse(c)
	}
	now := time.Now()
	resetPasswordToken := helper.RandomString(32)
	admin.ResetPasswordToken = &resetPasswordToken
	admin.ResetPasswordSentAt = &now
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
	if err = q.accountUseCase.UpdateAdmin(ctx, tx, admin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) AdminFindAdminByResetPasswordToken(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminFindAdminByResetPasswordToken"
	admins, _, err := q.accountUseCase.FindAdmins(
		ctx,
		accountModel.NewFilter(accountModel.WithResetPasswordToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAdmins")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(admins) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(admins[0]).WriteResponse(c)
}

func (q *accountHTTPHandler) AdminResetPassword(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminResetPassword"
	request, statusCode, err := sanitizer.ValidateResetPassword(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateResetPassword")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	admins, _, err := q.accountUseCase.FindAdmins(
		ctx,
		accountModel.NewFilter(accountModel.WithResetPasswordToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAdmins")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(admins) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	admin := admins[0]
	if admin.EncryptedPassword != nil &&
		helper.MatchedHashAndPassword(
			helper.String2ByteSlice(*admin.EncryptedPassword),
			helper.String2ByteSlice(request.Password),
		) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password reuse prohibited").WriteResponse(c)
	}
	now := time.Now()
	admin.ResetPasswordToken = nil
	admin.ResetPasswordSentAt = nil
	encryptedPassword, err := helper.HashPassword(request.Password)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrHashPassword")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	admin.EncryptedPassword = encryptedPassword
	admin.LastPasswordChange = &now
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
	jwt, err := q.jwtUseCase.CreateJWT(ctx, tx, admin.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	tokenString, err := helper.GenerateAccessToken(admin.ID, jwt.Token, admin.Username, jwt.CreatedAt, jwt.ExpiredAt)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = q.accountUseCase.UpdateAdmin(ctx, tx, admin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response := accountModel.AdminLoginResponse{
		LoginResponse: accountModel.LoginResponse{
			IDToken:   tokenString,
			ExpiredAt: jwt.ExpiredAt,
		},
		Account: admin,
	}
	return helper.NewResponse(fiber.StatusOK).SetData(response).WriteResponse(c)
}

func (q *accountHTTPHandler) AdminLogin(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-AdminLogin"
	request, statusCode, err := sanitizer.ValidateLogin(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateLogin")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	admins, _, err := q.accountUseCase.FindAdmins(
		ctx,
		accountModel.NewFilter(accountModel.WithLogin(request.Login)),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAdmins")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(admins) == 0 ||
		admins[0].Status != models.StatusConfirmed ||
		admins[0].EncryptedPassword == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	admin := admins[0]
	if admin.LoginLockedAt != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login locked out, max. failed attempts exceeded").WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*admin.EncryptedPassword)
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
		if admin.LoginFailedAttempts++; admin.LoginFailedAttempts >= helper.GetLoginMaxFailedAttempts() {
			loginLockoutToken := helper.RandomString(32)
			admin.LoginLockedAt = &now
			admin.LoginUnlockToken = &loginLockoutToken
		}
		if err = q.accountUseCase.UpdateAdmin(ctx, tx, admin); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
			return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
		}
		if admin.LoginLockedAt != nil {
			if _, err = q.jwtUseCase.DeleteJWTs(ctx, tx, jwtModel.NewDeleteFilter(jwtModel.WithAccountID(admin.ID))); err != nil {
				helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
				return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
			}
		}
		if err = tx.Commit(ctx); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
			return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
		}
		if admin.LoginLockedAt != nil {
			return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login locked out, max. failed attempts exceeded").WriteResponse(c)
		}
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	jwt, err := q.jwtUseCase.CreateJWT(ctx, tx, admin.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	tokenString, err := helper.GenerateAccessToken(admin.ID, jwt.Token, admin.Username, jwt.CreatedAt, jwt.ExpiredAt)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	ipAddress := c.IP()
	admin.LoginCount++
	admin.LastLoginAt = admin.CurrentLoginAt
	admin.LastLoginIP = admin.CurrentLoginIP
	admin.CurrentLoginAt = &now
	admin.CurrentLoginIP = &ipAddress
	admin.LoginFailedAttempts = 0
	if err = q.accountUseCase.UpdateAdmin(ctx, tx, admin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response := accountModel.AdminLoginResponse{
		LoginResponse: accountModel.LoginResponse{
			IDToken:   tokenString,
			ExpiredAt: jwt.ExpiredAt,
		},
		Account: admin,
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
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
	accounts, _, err := q.accountUseCase.FindAccounts(ctx, accountModel.NewFilter(accountModel.WithLogin(c.Params("id"))))
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
		accountModel.NewFilter(accountModel.WithLogin(c.Params("id"))),
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
	encryptedPassword := helper.String2ByteSlice(*currentAdmin.EncryptedPassword)
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(request.Password)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password: invalid").WriteResponse(c)
	}
	if currentAdmin.UnconfirmedEmail != nil && *currentAdmin.UnconfirmedEmail == request.Email {
		return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
	}
	if currentAdmin.Email != nil && *currentAdmin.Email == request.Email {
		currentAdmin.UnconfirmedEmail = nil
		currentAdmin.EmailConfirmationToken = nil
		currentAdmin.EmailConfirmationSentAt = nil
	} else {
		now := time.Now()
		emailConfirmationToken := helper.RandomString(32)
		currentAdmin.UnconfirmedEmail = &request.Email
		currentAdmin.EmailConfirmationToken = &emailConfirmationToken
		currentAdmin.EmailConfirmationSentAt = &now
	}
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
	encryptedPassword := helper.String2ByteSlice(*currentAdmin.EncryptedPassword)
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(request.Password)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password: invalid").WriteResponse(c)
	}
	if currentAdmin.UnconfirmedPhone != nil && *currentAdmin.UnconfirmedPhone == request.Phone {
		return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
	}
	if currentAdmin.Phone != nil && *currentAdmin.Phone == request.Phone {
		currentAdmin.UnconfirmedPhone = nil
		currentAdmin.PhoneConfirmationToken = nil
		currentAdmin.PhoneConfirmationSentAt = nil
	} else {
		now := time.Now()
		phoneConfirmationToken := helper.RandomNumber(6)
		currentAdmin.UnconfirmedPhone = &request.Phone
		currentAdmin.PhoneConfirmationToken = &phoneConfirmationToken
		currentAdmin.PhoneConfirmationSentAt = &now
	}
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

func (q *accountHTTPHandler) UserFindUserByConfirmationToken(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserFindUserByConfirmationToken"
	users, _, err := q.accountUseCase.FindUsers(
		ctx,
		accountModel.NewFilter(accountModel.WithConfirmationToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("account not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(users[0]).WriteResponse(c)
}

func (q *accountHTTPHandler) UserConfirmAccount(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserConfirmAccount"
	request, statusCode, err := sanitizer.ValidateConfirmation(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateConfirmation")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	users, _, err := q.accountUseCase.FindUsers(
		ctx,
		accountModel.NewFilter(accountModel.WithConfirmationToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	now := time.Now()
	user := users[0]
	user.Status = models.StatusConfirmed
	user.Name = request.Name
	user.Username = request.Username
	user.ConfirmationToken = nil
	user.ConfirmedAt = &now
	emailConfirmationToken, phoneConfirmationToken := helper.RandomString(32), helper.RandomNumber(6)
	if request.Email != nil &&
		(user.UnconfirmedEmail == nil ||
			*user.UnconfirmedEmail != *request.Email) {
		user.UnconfirmedEmail = request.Email
		user.EmailConfirmationToken = &emailConfirmationToken
		user.EmailConfirmationSentAt = &now
	}
	if request.Phone != nil &&
		(user.UnconfirmedPhone == nil ||
			*user.UnconfirmedPhone != *request.Phone) {
		user.UnconfirmedPhone = request.Phone
		user.PhoneConfirmationToken = &phoneConfirmationToken
		user.PhoneConfirmationSentAt = &now
	}
	encryptedPassword, err := helper.HashPassword(request.Password)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrHashPassword")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	user.EncryptedPassword = encryptedPassword
	user.LastPasswordChange = &now
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
	jwt, err := q.jwtUseCase.CreateJWT(ctx, tx, user.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	tokenString, err := helper.GenerateAccessToken(user.ID, jwt.Token, user.Username, jwt.CreatedAt, jwt.ExpiredAt)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	ipAddress := c.IP()
	user.LoginCount++
	user.LastLoginAt = user.CurrentLoginAt
	user.LastLoginIP = user.CurrentLoginIP
	user.CurrentLoginAt = &now
	user.CurrentLoginIP = &ipAddress
	if err = q.accountUseCase.UpdateUser(ctx, tx, user); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response := accountModel.UserLoginResponse{
		LoginResponse: accountModel.LoginResponse{
			IDToken:   tokenString,
			ExpiredAt: jwt.ExpiredAt,
		},
		Account: user,
	}
	return helper.NewResponse(fiber.StatusOK).SetData(response).WriteResponse(c)
}

func (q *accountHTTPHandler) UserConfirmEmail(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserConfirmEmail"
	users, _, err := q.accountUseCase.FindUsers(
		ctx,
		accountModel.NewFilter(accountModel.WithEmailConfirmationToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	now := time.Now()
	user := users[0]
	email := *user.UnconfirmedEmail
	user.Email = &email
	user.UnconfirmedEmail = nil
	user.EmailConfirmationToken = nil
	user.EmailConfirmationSentAt = nil
	user.EmailConfirmedAt = &now
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
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) UserConfirmPhone(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserConfirmPhone"
	users, _, err := q.accountUseCase.FindUsers(
		ctx,
		accountModel.NewFilter(accountModel.WithPhoneConfirmationToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	now := time.Now()
	user := users[0]
	phone := *user.UnconfirmedPhone
	user.Phone = &phone
	user.UnconfirmedPhone = nil
	user.PhoneConfirmationToken = nil
	user.PhoneConfirmationSentAt = nil
	user.PhoneConfirmedAt = &now
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
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) UserUnlockAccount(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserUnlockAccount"
	users, _, err := q.accountUseCase.FindUsers(
		ctx,
		accountModel.NewFilter(accountModel.WithLoginUnlockToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	account := users[0]
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
	if err = q.accountUseCase.UpdateUser(ctx, tx, account); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) UserForgotPassword(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserForgotPassword"
	request, statusCode, err := sanitizer.ValidateForgotPassword(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateForgotPassword")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	users, _, err := q.accountUseCase.FindUsers(
		ctx,
		accountModel.NewFilter(accountModel.WithLogin(request.Login)),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("login not found").WriteResponse(c)
	}
	user := users[0]
	if user.Status != models.StatusConfirmed {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("cannot reset password for unconfirmed/deactivated account").WriteResponse(c)
	}
	if user.LoginLockedAt != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("cannot reset password for locked out account").WriteResponse(c)
	}
	now := time.Now()
	resetPasswordToken := helper.RandomString(32)
	user.ResetPasswordToken = &resetPasswordToken
	user.ResetPasswordSentAt = &now
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
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountHTTPHandler) UserFindUserByResetPasswordToken(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserFindUserByResetPasswordToken"
	users, _, err := q.accountUseCase.FindUsers(
		ctx,
		accountModel.NewFilter(accountModel.WithResetPasswordToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(users[0]).WriteResponse(c)
}

func (q *accountHTTPHandler) UserResetPassword(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserResetPassword"
	request, statusCode, err := sanitizer.ValidateResetPassword(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateResetPassword")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	users, _, err := q.accountUseCase.FindUsers(
		ctx,
		accountModel.NewFilter(accountModel.WithResetPasswordToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	user := users[0]
	if user.EncryptedPassword != nil &&
		helper.MatchedHashAndPassword(
			helper.String2ByteSlice(*user.EncryptedPassword),
			helper.String2ByteSlice(request.Password),
		) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password reuse prohibited").WriteResponse(c)
	}
	now := time.Now()
	user.ResetPasswordToken = nil
	user.ResetPasswordSentAt = nil
	encryptedPassword, err := helper.HashPassword(request.Password)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrHashPassword")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	user.EncryptedPassword = encryptedPassword
	user.LastPasswordChange = &now
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
	jwt, err := q.jwtUseCase.CreateJWT(ctx, tx, user.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	tokenString, err := helper.GenerateAccessToken(user.ID, jwt.Token, user.Username, jwt.CreatedAt, jwt.ExpiredAt)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = q.accountUseCase.UpdateUser(ctx, tx, user); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response := accountModel.UserLoginResponse{
		LoginResponse: accountModel.LoginResponse{
			IDToken:   tokenString,
			ExpiredAt: jwt.ExpiredAt,
		},
		Account: user,
	}
	return helper.NewResponse(fiber.StatusOK).SetData(response).WriteResponse(c)
}

func (q *accountHTTPHandler) UserLogin(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-UserLogin"
	request, statusCode, err := sanitizer.ValidateLogin(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateLogin")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	users, _, err := q.accountUseCase.FindUsers(
		ctx,
		accountModel.NewFilter(accountModel.WithLogin(request.Login)),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 ||
		users[0].Status != models.StatusConfirmed ||
		users[0].EncryptedPassword == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	user := users[0]
	if user.LoginLockedAt != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login locked out, max. failed attempts exceeded").WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*user.EncryptedPassword)
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
		if user.LoginFailedAttempts++; user.LoginFailedAttempts >= helper.GetLoginMaxFailedAttempts() {
			loginLockoutToken := helper.RandomString(32)
			user.LoginLockedAt = &now
			user.LoginUnlockToken = &loginLockoutToken
		}
		if err = q.accountUseCase.UpdateUser(ctx, tx, user); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
			return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
		}
		if user.LoginLockedAt != nil {
			if _, err = q.jwtUseCase.DeleteJWTs(ctx, tx, jwtModel.NewDeleteFilter(jwtModel.WithAccountID(user.ID))); err != nil {
				helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
				return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
			}
		}
		if err = tx.Commit(ctx); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
			return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
		}
		if user.LoginLockedAt != nil {
			return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login locked out, max. failed attempts exceeded").WriteResponse(c)
		}
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	jwt, err := q.jwtUseCase.CreateJWT(ctx, tx, user.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	tokenString, err := helper.GenerateAccessToken(user.ID, jwt.Token, user.Username, jwt.CreatedAt, jwt.ExpiredAt)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	ipAddress := c.IP()
	user.LoginCount++
	user.LastLoginAt = user.CurrentLoginAt
	user.LastLoginIP = user.CurrentLoginIP
	user.CurrentLoginAt = &now
	user.CurrentLoginIP = &ipAddress
	user.LoginFailedAttempts = 0
	if err = q.accountUseCase.UpdateUser(ctx, tx, user); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response := accountModel.UserLoginResponse{
		LoginResponse: accountModel.LoginResponse{
			IDToken:   tokenString,
			ExpiredAt: jwt.ExpiredAt,
		},
		Account: user,
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
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
	users, _, err := q.accountUseCase.FindUsers(ctx, accountModel.NewFilter(accountModel.WithLogin(c.Params("id")), accountModel.WithCompanyIDs(currentUser.CompanyID)))
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
		accountModel.NewFilter(accountModel.WithLogin(c.Params("id")), accountModel.WithCompanyIDs(currentUser.CompanyID)),
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
	if helper.MatchedHashAndPassword(oldEncryptedPassword, helper.String2ByteSlice(request.NewPassword)) {
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
	encryptedPassword := helper.String2ByteSlice(*currentUser.EncryptedPassword)
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(request.Password)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password: invalid").WriteResponse(c)
	}
	if currentUser.UnconfirmedEmail != nil && *currentUser.UnconfirmedEmail == request.Email {
		return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
	}
	if currentUser.Email != nil && *currentUser.Email == request.Email {
		currentUser.UnconfirmedEmail = nil
		currentUser.EmailConfirmationToken = nil
		currentUser.EmailConfirmationSentAt = nil
	} else {
		now := time.Now()
		emailConfirmationToken := helper.RandomString(32)
		currentUser.UnconfirmedEmail = &request.Email
		currentUser.EmailConfirmationToken = &emailConfirmationToken
		currentUser.EmailConfirmationSentAt = &now
	}
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
	encryptedPassword := helper.String2ByteSlice(*currentUser.EncryptedPassword)
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(request.Password)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password: invalid").WriteResponse(c)
	}
	if currentUser.UnconfirmedPhone != nil && *currentUser.UnconfirmedPhone == request.Phone {
		return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
	}
	if currentUser.Phone != nil && *currentUser.Phone == request.Phone {
		currentUser.UnconfirmedPhone = nil
		currentUser.PhoneConfirmationToken = nil
		currentUser.PhoneConfirmationSentAt = nil
	} else {
		now := time.Now()
		phoneConfirmationToken := helper.RandomNumber(6)
		currentUser.UnconfirmedPhone = &request.Phone
		currentUser.PhoneConfirmationToken = &phoneConfirmationToken
		currentUser.PhoneConfirmationSentAt = &now
	}
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
