package controllers

import (
	"errors"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/repositories"
	"github.com/roysitumorang/sadia/sanitizers"
	"github.com/roysitumorang/sadia/services"
	"go.uber.org/zap"
)

type accountController struct {
	jwtService     services.JwtService
	accountService services.AccountService
	companyService services.CompanyService
	sessionService services.SessionService
}

func NewAccountController(
	jwtService services.JwtService,
	accountService services.AccountService,
	companyService services.CompanyService,
	sessionService services.SessionService,
) *accountController {
	return &accountController{
		jwtService:     jwtService,
		accountService: accountService,
		companyService: companyService,
		sessionService: sessionService,
	}
}

func (q *accountController) Mount(r fiber.Router) {
	adminKeyAuth := middleware.AdminKeyAuth(q.jwtService, q.accountService)
	superAdminKeyAuth := middleware.AdminKeyAuth(q.jwtService, q.accountService, models.AdminLevelSuperAdmin)
	v1 := r.Group("/v1")
	admin := v1.Group("/admin")
	admin.Get("/confirmation/:token", q.AdminFindAdminByConfirmationToken).
		Put("/confirmation/:token", q.AdminConfirmAccount).
		Get("/email/confirm/:token", q.AdminConfirmEmail).
		Get("/phone/confirm/:token", q.AdminConfirmPhone).
		Get("/unlock/:token", q.AdminUnlockAccount).
		Put("/password/forgot", q.AdminForgotPassword).
		Get("/password/reset/:token", q.AdminFindAdminByResetPasswordToken).
		Put("/password/reset/:token", q.AdminResetPassword).
		Post("/login", q.AdminLogin)
	admin.Group("/admins").
		Get("", adminKeyAuth, q.AdminFindAdmins).
		Post("", superAdminKeyAuth, q.AdminCreateAdmin).
		Get("/:id", adminKeyAuth, q.AdminFindAdminByID).
		Delete("/:id", superAdminKeyAuth, q.AdminDeactivateAdmin)
	admin.Group("/users").
		Get("", adminKeyAuth, q.AdminFindUsers).
		Get("/:id", adminKeyAuth, q.AdminFindUserByID).
		Delete("/:id", superAdminKeyAuth, q.AdminDeactivateUser)
	admin.Group("/me").
		Get("/about", adminKeyAuth, q.AdminProfile).
		Put("/password", adminKeyAuth, q.AdminChangePassword).
		Put("/username", adminKeyAuth, q.AdminChangeUsername).
		Put("/email", adminKeyAuth, q.AdminChangeEmail).
		Put("/phone", adminKeyAuth, q.AdminChangePhone)
	userKeyAuth := middleware.UserKeyAuth(q.jwtService, q.accountService, q.companyService, q.sessionService)
	ownerKeyAuth := middleware.UserKeyAuth(q.jwtService, q.accountService, q.companyService, q.sessionService, models.UserLevelOwner)
	v1.Get("/confirmation/:token", q.UserFindUserByConfirmationToken).
		Put("/confirmation/:token", q.UserConfirmAccount).
		Get("/email/confirm/:token", q.UserConfirmEmail).
		Get("/phone/confirm/:token", q.UserConfirmPhone).
		Get("/unlock/:token", q.UserUnlockAccount).
		Put("/password/forgot", q.UserForgotPassword).
		Get("/password/reset/:token", q.UserFindUserByResetPasswordToken).
		Put("/password/reset/:token", q.UserResetPassword).
		Post("/login", q.UserLogin)
	users := v1.Group("/users")
	users.Get("", ownerKeyAuth, q.UserFindUsers).
		Post("", ownerKeyAuth, q.UserCreateUser).
		Get("/:id", ownerKeyAuth, q.UserFindUserByID).
		Delete("/:id", ownerKeyAuth, q.UserDeactivateUser)
	me := v1.Group("/me")
	me.Get("/about", userKeyAuth, q.UserProfile).
		Put("/password", userKeyAuth, q.UserChangePassword).
		Put("/username", userKeyAuth, q.UserChangeUsername).
		Put("/email", userKeyAuth, q.UserChangeEmail).
		Put("/phone", userKeyAuth, q.UserChangePhone)
	userSessionAuth := middleware.UserSessionAuth(q.accountService, q.companyService, q.sessionService)
	r.Get("/login", q.userNewLogin).
		Post("/login", q.userLogin).
		Get("/logout", q.userLogout).
		Get("/me", userSessionAuth, q.userProfile)
}

func (q *accountController) AdminFindAdminByConfirmationToken(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminFindAdminByConfirmationToken"
	admins, _, err := q.accountService.FindAdmins(
		ctx,
		models.NewAccountFilter(models.AccountWithConfirmationToken(c.Params("token"))),
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

func (q *accountController) AdminConfirmAccount(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminConfirmAccount"
	request, statusCode, err := sanitizers.ValidateConfirmation(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateConfirmation")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	admins, _, err := q.accountService.FindAdmins(
		ctx,
		models.NewAccountFilter(models.AccountWithConfirmationToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAdmins")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(admins) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	now := time.Now()
	oldAdmin := admins[0]
	oldAdmin.Status = models.StatusConfirmed
	oldAdmin.Name = request.Name
	oldAdmin.Username = request.Username
	oldAdmin.ConfirmationToken = nil
	oldAdmin.ConfirmedAt = &now
	emailConfirmationToken, phoneConfirmationToken := helper.RandomString(32), helper.RandomNumber(6)
	if request.Email != nil &&
		(oldAdmin.UnconfirmedEmail == nil ||
			*oldAdmin.UnconfirmedEmail != *request.Email) {
		oldAdmin.UnconfirmedEmail = request.Email
		oldAdmin.EmailConfirmationToken = &emailConfirmationToken
		oldAdmin.EmailConfirmationSentAt = &now
	}
	if request.Phone != nil &&
		(oldAdmin.UnconfirmedPhone == nil ||
			*oldAdmin.UnconfirmedPhone != *request.Phone) {
		oldAdmin.UnconfirmedPhone = request.Phone
		oldAdmin.PhoneConfirmationToken = &phoneConfirmationToken
		oldAdmin.PhoneConfirmationSentAt = &now
	}
	encryptedPassword, err := helper.HashPassword(request.Password)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrHashPassword")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	oldAdmin.EncryptedPassword = encryptedPassword
	oldAdmin.LastPasswordChange = &now
	tx, err := repositories.BeginTx(ctx)
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
	jwt, err := q.jwtService.CreateJWT(ctx, tx, oldAdmin.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	tokenString, err := helper.GenerateAccessToken(strconv.FormatUint(oldAdmin.ID, 10), jwt.Token, oldAdmin.Username, jwt.CreatedAt, jwt.ExpiredAt)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	ipAddress := c.IP()
	oldAdmin.LoginCount++
	oldAdmin.LastLoginAt = oldAdmin.CurrentLoginAt
	oldAdmin.LastLoginIP = oldAdmin.CurrentLoginIP
	oldAdmin.CurrentLoginAt = &now
	oldAdmin.CurrentLoginIP = &ipAddress
	newAdmin, err := q.accountService.UpdateAdmin(ctx, tx, oldAdmin)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response := models.AdminLoginResponse{
		IDToken:   tokenString,
		ExpiredAt: jwt.ExpiredAt,
		Account:   newAdmin,
	}
	return helper.NewResponse(fiber.StatusOK).SetData(response).WriteResponse(c)
}

func (q *accountController) AdminConfirmEmail(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminConfirmEmail"
	admins, _, err := q.accountService.FindAdmins(
		ctx,
		models.NewAccountFilter(models.AccountWithEmailConfirmationToken(c.Params("token"))),
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
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.accountService.UpdateAdmin(ctx, tx, admin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountController) AdminConfirmPhone(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminConfirmPhone"
	admins, _, err := q.accountService.FindAdmins(
		ctx,
		models.NewAccountFilter(models.AccountWithPhoneConfirmationToken(c.Params("token"))),
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
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.accountService.UpdateAdmin(ctx, tx, admin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountController) AdminUnlockAccount(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminUnlockAccount"
	admins, _, err := q.accountService.FindAdmins(
		ctx,
		models.NewAccountFilter(models.AccountWithLoginUnlockToken(c.Params("token"))),
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
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.accountService.UpdateAdmin(ctx, tx, admin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountController) AdminForgotPassword(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminForgotPassword"
	request, statusCode, err := sanitizers.ValidateForgotPassword(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateForgotPassword")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	admins, _, err := q.accountService.FindAdmins(
		ctx,
		models.NewAccountFilter(models.AccountWithLogin(request.Login)),
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
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.accountService.UpdateAdmin(ctx, tx, admin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountController) AdminFindAdminByResetPasswordToken(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminFindAdminByResetPasswordToken"
	admins, _, err := q.accountService.FindAdmins(
		ctx,
		models.NewAccountFilter(models.AccountWithResetPasswordToken(c.Params("token"))),
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

func (q *accountController) AdminResetPassword(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminResetPassword"
	request, statusCode, err := sanitizers.ValidateResetPassword(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateResetPassword")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	admins, _, err := q.accountService.FindAdmins(
		ctx,
		models.NewAccountFilter(models.AccountWithResetPasswordToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAdmins")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(admins) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	oldAdmin := admins[0]
	if oldAdmin.EncryptedPassword != nil &&
		helper.MatchedHashAndPassword(
			helper.String2ByteSlice(*oldAdmin.EncryptedPassword),
			helper.String2ByteSlice(request.Password),
		) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password reuse prohibited").WriteResponse(c)
	}
	now := time.Now()
	oldAdmin.ResetPasswordToken = nil
	oldAdmin.ResetPasswordSentAt = nil
	encryptedPassword, err := helper.HashPassword(request.Password)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrHashPassword")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	oldAdmin.EncryptedPassword = encryptedPassword
	oldAdmin.LastPasswordChange = &now
	tx, err := repositories.BeginTx(ctx)
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
	jwt, err := q.jwtService.CreateJWT(ctx, tx, oldAdmin.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	tokenString, err := helper.GenerateAccessToken(strconv.FormatUint(oldAdmin.ID, 10), jwt.Token, oldAdmin.Username, jwt.CreatedAt, jwt.ExpiredAt)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	newAdmin, err := q.accountService.UpdateAdmin(ctx, tx, oldAdmin)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response := models.AdminLoginResponse{
		IDToken:   tokenString,
		ExpiredAt: jwt.ExpiredAt,
		Account:   newAdmin,
	}
	return helper.NewResponse(fiber.StatusOK).SetData(response).WriteResponse(c)
}

func (q *accountController) AdminLogin(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminLogin"
	request, statusCode, err := sanitizers.ValidateLogin(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateLogin")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	admins, _, err := q.accountService.FindAdmins(
		ctx,
		models.NewAccountFilter(models.AccountWithLogin(request.Login)),
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
	oldAdmin := admins[0]
	if oldAdmin.LoginLockedAt != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login locked out, max. failed attempts exceeded").WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*oldAdmin.EncryptedPassword)
	now := time.Now()
	tx, err := repositories.BeginTx(ctx)
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
		if oldAdmin.LoginFailedAttempts++; oldAdmin.LoginFailedAttempts >= helper.GetLoginMaxFailedAttempts() {
			loginLockoutToken := helper.RandomString(32)
			oldAdmin.LoginLockedAt = &now
			oldAdmin.LoginUnlockToken = &loginLockoutToken
		}
		newAdmin, err := q.accountService.UpdateAdmin(ctx, tx, oldAdmin)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
			return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
		}
		if newAdmin.LoginLockedAt != nil {
			if _, err = q.jwtService.DeleteJWTs(ctx, tx, models.NewJwtDeleteFilter(models.JwtWithDeleteAccountID(newAdmin.ID))); err != nil {
				helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
				return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
			}
		}
		if err = tx.Commit(ctx); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
			return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
		}
		if newAdmin.LoginLockedAt != nil {
			return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login locked out, max. failed attempts exceeded").WriteResponse(c)
		}
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	jwt, err := q.jwtService.CreateJWT(ctx, tx, oldAdmin.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	tokenString, err := helper.GenerateAccessToken(strconv.FormatUint(oldAdmin.ID, 10), jwt.Token, oldAdmin.Username, jwt.CreatedAt, jwt.ExpiredAt)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	ipAddress := c.IP()
	oldAdmin.LoginCount++
	oldAdmin.LastLoginAt = oldAdmin.CurrentLoginAt
	oldAdmin.LastLoginIP = oldAdmin.CurrentLoginIP
	oldAdmin.CurrentLoginAt = &now
	oldAdmin.CurrentLoginIP = &ipAddress
	oldAdmin.LoginFailedAttempts = 0
	newAdmin, err := q.accountService.UpdateAdmin(ctx, tx, oldAdmin)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response := models.AdminLoginResponse{
		IDToken:   tokenString,
		ExpiredAt: jwt.ExpiredAt,
		Account:   newAdmin,
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *accountController) AdminFindAdmins(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminFindAdmins"
	filter, err := sanitizers.FindAdmins(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAdmins")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	rows, pagination, err := q.accountService.FindAdmins(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAdmins")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *accountController) AdminCreateAdmin(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminCreateAdmin"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*models.Admin)
	request, statusCode, err := sanitizers.ValidateAdmin(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateAdmin")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	request.CreatedBy = &currentAdmin.ID
	tx, err := repositories.BeginTx(ctx)
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
	response, err := q.accountService.CreateAdmin(ctx, tx, request)
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

func (q *accountController) AdminFindAdminByID(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminFindAdminByID"
	adminID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("admin not found").WriteResponse(c)
	}
	admins, _, err := q.accountService.FindAdmins(
		ctx,
		models.NewAccountFilter(models.AccountWithAccountIDs(adminID)),
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

func (q *accountController) AdminDeactivateAdmin(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminDeactivateAdmin"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*models.Admin)
	adminID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("admin not found").WriteResponse(c)
	}
	request, statusCode, err := sanitizers.ValidateAccountDeactivation(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateAccountDeactivation")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	if currentAdmin.ID == adminID {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("self deactivation prohibited").WriteResponse(c)
	}
	admins, _, err := q.accountService.FindAdmins(
		ctx,
		models.NewAccountFilter(models.AccountWithAccountIDs(adminID)),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAdmins")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(admins) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("admin not found").WriteResponse(c)
	}
	oldAdmin := admins[0]
	if oldAdmin.Status != models.StatusConfirmed {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("cannot deactivate unconfirmed & deactivated account").WriteResponse(c)
	}
	now := time.Now()
	oldAdmin.Status = models.StatusDeactivated
	oldAdmin.DeactivatedBy = &currentAdmin.ID
	oldAdmin.DeactivatedAt = &now
	oldAdmin.DeactivationReason = &request.Reason
	tx, err := repositories.BeginTx(ctx)
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
	newAdmin, err := q.accountService.UpdateAdmin(ctx, tx, oldAdmin)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if _, err = q.jwtService.DeleteJWTs(ctx, tx, models.NewJwtDeleteFilter(models.JwtWithDeleteAccountID(newAdmin.ID))); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(newAdmin).WriteResponse(c)
}

func (q *accountController) AdminFindUsers(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminFindUsers"
	filter, err := sanitizers.FindUsers(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	rows, pagination, err := q.accountService.FindUsers(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *accountController) AdminFindUserByID(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminFindUserByID"
	userID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("user not found").WriteResponse(c)
	}
	users, _, err := q.accountService.FindUsers(
		ctx,
		models.NewAccountFilter(models.AccountWithAccountIDs(userID)),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("user not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(users[0]).WriteResponse(c)
}

func (q *accountController) AdminDeactivateUser(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminDeactivateUser"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*models.Admin)
	userID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("user not found").WriteResponse(c)
	}
	request, statusCode, err := sanitizers.ValidateAccountDeactivation(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateAccountDeactivation")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	users, _, err := q.accountService.FindUsers(
		ctx,
		models.NewAccountFilter(models.AccountWithAccountIDs(userID)),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("user not found").WriteResponse(c)
	}
	oldUser := users[0]
	if oldUser.Status != models.StatusConfirmed {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("cannot deactivate unconfirmed & deactivated user").WriteResponse(c)
	}
	now := time.Now()
	oldUser.Status = models.StatusDeactivated
	oldUser.DeactivatedBy = &currentAdmin.ID
	oldUser.DeactivatedAt = &now
	oldUser.DeactivationReason = &request.Reason
	tx, err := repositories.BeginTx(ctx)
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
	newUser, err := q.accountService.UpdateUser(ctx, tx, oldUser)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if _, err = q.jwtService.DeleteJWTs(ctx, tx, models.NewJwtDeleteFilter(models.JwtWithDeleteAccountID(newUser.ID))); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(newUser).WriteResponse(c)
}

func (q *accountController) AdminProfile(c fiber.Ctx) error {
	response := c.Locals(models.CurrentAdmin)
	return helper.NewResponse(fiber.StatusOK).SetData(response).WriteResponse(c)
}

func (q *accountController) AdminChangePassword(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminChangePassword"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*models.Admin)
	request, statusCode, err := sanitizers.ValidateChangePassword(ctx, c)
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
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.accountService.UpdateAdmin(ctx, tx, currentAdmin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountController) AdminChangeUsername(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminChangeUsername"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*models.Admin)
	request, statusCode, err := sanitizers.ValidateChangeUsername(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateChangeUsername")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*currentAdmin.EncryptedPassword)
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(request.Password)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password: invalid").WriteResponse(c)
	}
	if currentAdmin.Username == request.Username {
		return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
	}
	accounts, _, err := q.accountService.FindAccounts(
		ctx,
		models.NewAccountFilter(
			models.AccountWithUsername(request.Username),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) > 0 && accounts[0].ID != currentAdmin.ID {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("username already exists").WriteResponse(c)
	}
	now := time.Now()
	currentAdmin.Username = request.Username
	currentAdmin.UpdatedAt = now
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.accountService.UpdateAdmin(ctx, tx, currentAdmin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountController) AdminChangeEmail(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminChangeEmail"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*models.Admin)
	request, statusCode, err := sanitizers.ValidateChangeEmail(ctx, c)
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
	accounts, _, err := q.accountService.FindAccounts(
		ctx,
		models.NewAccountFilter(
			models.AccountWithEmail(request.Email),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) > 0 && accounts[0].ID != currentAdmin.ID {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("email already exists").WriteResponse(c)
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
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.accountService.UpdateAdmin(ctx, tx, currentAdmin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountController) AdminChangePhone(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-AdminChangePhone"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*models.Admin)
	request, statusCode, err := sanitizers.ValidateChangePhone(ctx, c)
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
	accounts, _, err := q.accountService.FindAccounts(
		ctx,
		models.NewAccountFilter(
			models.AccountWithPhone(request.Phone),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) > 0 && accounts[0].ID != currentAdmin.ID {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("phone already exists").WriteResponse(c)
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
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.accountService.UpdateAdmin(ctx, tx, currentAdmin); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountController) UserFindUserByConfirmationToken(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserFindUserByConfirmationToken"
	users, _, err := q.accountService.FindUsers(
		ctx,
		models.NewAccountFilter(models.AccountWithConfirmationToken(c.Params("token"))),
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

func (q *accountController) UserConfirmAccount(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserConfirmAccount"
	request, statusCode, err := sanitizers.ValidateConfirmation(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateConfirmation")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	users, _, err := q.accountService.FindUsers(
		ctx,
		models.NewAccountFilter(models.AccountWithConfirmationToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	now := time.Now()
	oldUser := users[0]
	oldUser.Status = models.StatusConfirmed
	oldUser.Name = request.Name
	oldUser.Username = request.Username
	oldUser.ConfirmationToken = nil
	oldUser.ConfirmedAt = &now
	emailConfirmationToken, phoneConfirmationToken := helper.RandomString(32), helper.RandomNumber(6)
	if request.Email != nil &&
		(oldUser.UnconfirmedEmail == nil ||
			*oldUser.UnconfirmedEmail != *request.Email) {
		oldUser.UnconfirmedEmail = request.Email
		oldUser.EmailConfirmationToken = &emailConfirmationToken
		oldUser.EmailConfirmationSentAt = &now
	}
	if request.Phone != nil &&
		(oldUser.UnconfirmedPhone == nil ||
			*oldUser.UnconfirmedPhone != *request.Phone) {
		oldUser.UnconfirmedPhone = request.Phone
		oldUser.PhoneConfirmationToken = &phoneConfirmationToken
		oldUser.PhoneConfirmationSentAt = &now
	}
	encryptedPassword, err := helper.HashPassword(request.Password)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrHashPassword")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	oldUser.EncryptedPassword = encryptedPassword
	oldUser.LastPasswordChange = &now
	tx, err := repositories.BeginTx(ctx)
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
	jwt, err := q.jwtService.CreateJWT(ctx, tx, oldUser.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	tokenString, err := helper.GenerateAccessToken(strconv.FormatUint(oldUser.ID, 10), jwt.Token, oldUser.Username, jwt.CreatedAt, jwt.ExpiredAt)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	ipAddress := c.IP()
	oldUser.LoginCount++
	oldUser.LastLoginAt = oldUser.CurrentLoginAt
	oldUser.LastLoginIP = oldUser.CurrentLoginIP
	oldUser.CurrentLoginAt = &now
	oldUser.CurrentLoginIP = &ipAddress
	newUser, err := q.accountService.UpdateUser(ctx, tx, oldUser)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response := models.UserLoginResponse{
		IDToken:   tokenString,
		ExpiredAt: jwt.ExpiredAt,
		Account:   newUser,
	}
	return helper.NewResponse(fiber.StatusOK).SetData(response).WriteResponse(c)
}

func (q *accountController) UserConfirmEmail(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserConfirmEmail"
	users, _, err := q.accountService.FindUsers(
		ctx,
		models.NewAccountFilter(models.AccountWithEmailConfirmationToken(c.Params("token"))),
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
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.accountService.UpdateUser(ctx, tx, user); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountController) UserConfirmPhone(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserConfirmPhone"
	users, _, err := q.accountService.FindUsers(
		ctx,
		models.NewAccountFilter(models.AccountWithPhoneConfirmationToken(c.Params("token"))),
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
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.accountService.UpdateUser(ctx, tx, user); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountController) UserUnlockAccount(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserUnlockAccount"
	users, _, err := q.accountService.FindUsers(
		ctx,
		models.NewAccountFilter(models.AccountWithLoginUnlockToken(c.Params("token"))),
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
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.accountService.UpdateUser(ctx, tx, account); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountController) UserForgotPassword(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserForgotPassword"
	request, statusCode, err := sanitizers.ValidateForgotPassword(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateForgotPassword")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	users, _, err := q.accountService.FindUsers(
		ctx,
		models.NewAccountFilter(models.AccountWithLogin(request.Login)),
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
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.accountService.UpdateUser(ctx, tx, user); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountController) UserFindUserByResetPasswordToken(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserFindUserByResetPasswordToken"
	users, _, err := q.accountService.FindUsers(
		ctx,
		models.NewAccountFilter(models.AccountWithResetPasswordToken(c.Params("token"))),
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

func (q *accountController) UserResetPassword(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserResetPassword"
	request, statusCode, err := sanitizers.ValidateResetPassword(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateResetPassword")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	users, _, err := q.accountService.FindUsers(
		ctx,
		models.NewAccountFilter(models.AccountWithResetPasswordToken(c.Params("token"))),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("token not found").WriteResponse(c)
	}
	oldUser := users[0]
	if oldUser.EncryptedPassword != nil &&
		helper.MatchedHashAndPassword(
			helper.String2ByteSlice(*oldUser.EncryptedPassword),
			helper.String2ByteSlice(request.Password),
		) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password reuse prohibited").WriteResponse(c)
	}
	now := time.Now()
	oldUser.ResetPasswordToken = nil
	oldUser.ResetPasswordSentAt = nil
	encryptedPassword, err := helper.HashPassword(request.Password)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrHashPassword")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	oldUser.EncryptedPassword = encryptedPassword
	oldUser.LastPasswordChange = &now
	tx, err := repositories.BeginTx(ctx)
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
	jwt, err := q.jwtService.CreateJWT(ctx, tx, oldUser.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	tokenString, err := helper.GenerateAccessToken(strconv.FormatUint(oldUser.ID, 10), jwt.Token, oldUser.Username, jwt.CreatedAt, jwt.ExpiredAt)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	newUser, err := q.accountService.UpdateUser(ctx, tx, oldUser)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response := models.UserLoginResponse{
		IDToken:   tokenString,
		ExpiredAt: jwt.ExpiredAt,
		Account:   newUser,
	}
	return helper.NewResponse(fiber.StatusOK).SetData(response).WriteResponse(c)
}

func (q *accountController) UserLogin(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserLogin"
	request, statusCode, err := sanitizers.ValidateLogin(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateLogin")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	users, _, err := q.accountService.FindUsers(
		ctx,
		models.NewAccountFilter(models.AccountWithLogin(request.Login)),
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
	oldUser := users[0]
	if oldUser.LoginLockedAt != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login locked out, max. failed attempts exceeded").WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*oldUser.EncryptedPassword)
	now := time.Now()
	tx, err := repositories.BeginTx(ctx)
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
		if oldUser.LoginFailedAttempts++; oldUser.LoginFailedAttempts >= helper.GetLoginMaxFailedAttempts() {
			loginLockoutToken := helper.RandomString(32)
			oldUser.LoginLockedAt = &now
			oldUser.LoginUnlockToken = &loginLockoutToken
		}
		newUser, err := q.accountService.UpdateUser(ctx, tx, oldUser)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
			return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
		}
		if newUser.LoginLockedAt != nil {
			if _, err = q.jwtService.DeleteJWTs(ctx, tx, models.NewJwtDeleteFilter(models.JwtWithDeleteAccountID(newUser.ID))); err != nil {
				helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
				return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
			}
		}
		if err = tx.Commit(ctx); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
			return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
		}
		if newUser.LoginLockedAt != nil {
			return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login locked out, max. failed attempts exceeded").WriteResponse(c)
		}
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	jwt, err := q.jwtService.CreateJWT(ctx, tx, oldUser.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	tokenString, err := helper.GenerateAccessToken(strconv.FormatUint(oldUser.ID, 10), jwt.Token, oldUser.Username, jwt.CreatedAt, jwt.ExpiredAt)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	ipAddress := c.IP()
	oldUser.LoginCount++
	oldUser.LastLoginAt = oldUser.CurrentLoginAt
	oldUser.LastLoginIP = oldUser.CurrentLoginIP
	oldUser.CurrentLoginAt = &now
	oldUser.CurrentLoginIP = &ipAddress
	oldUser.LoginFailedAttempts = 0
	newUser, err := q.accountService.UpdateUser(ctx, tx, oldUser)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response := models.UserLoginResponse{
		IDToken:   tokenString,
		ExpiredAt: jwt.ExpiredAt,
		Account:   newUser,
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *accountController) UserFindUsers(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserFindUsers"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	filter, err := sanitizers.FindAccounts(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	filter.CompanyIDs = []uint64{currentUser.CompanyID}
	rows, pagination, err := q.accountService.FindUsers(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *accountController) UserCreateUser(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserCreateUser"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	request, statusCode, err := sanitizers.ValidateUser(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateUser")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	request.CompanyID = currentUser.CompanyID
	request.CreatedBy = &currentUser.ID
	tx, err := repositories.BeginTx(ctx)
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
	response, err := q.accountService.CreateUser(ctx, tx, request)
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

func (q *accountController) UserFindUserByID(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserFindUserByID"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	userID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("user not found").WriteResponse(c)
	}
	users, _, err := q.accountService.FindUsers(ctx, models.NewAccountFilter(models.AccountWithAccountIDs(userID), models.AccountWithCompanyIDs(currentUser.CompanyID)))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("user not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(users[0]).WriteResponse(c)
}

func (q *accountController) UserDeactivateUser(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserDeactivateUser"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	userID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("user not found").WriteResponse(c)
	}
	if currentUser.ID == userID {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("self deactivation prohibited").WriteResponse(c)
	}
	request, statusCode, err := sanitizers.ValidateAccountDeactivation(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateAccountDeactivation")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	users, _, err := q.accountService.FindUsers(
		ctx,
		models.NewAccountFilter(models.AccountWithAccountIDs(userID), models.AccountWithCompanyIDs(currentUser.CompanyID)),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(users) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("user not found").WriteResponse(c)
	}
	oldUser := users[0]
	if oldUser.Status != models.StatusConfirmed {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("cannot deactivate unconfirmed & deactivated user").WriteResponse(c)
	}
	now := time.Now()
	oldUser.Status = models.StatusDeactivated
	oldUser.DeactivatedBy = &currentUser.ID
	oldUser.DeactivatedAt = &now
	oldUser.DeactivationReason = &request.Reason
	tx, err := repositories.BeginTx(ctx)
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
	newUser, err := q.accountService.UpdateUser(ctx, tx, oldUser)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if _, err = q.jwtService.DeleteJWTs(ctx, tx, models.NewJwtDeleteFilter(models.JwtWithDeleteAccountID(newUser.ID))); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(newUser).WriteResponse(c)
}

func (q *accountController) UserProfile(c fiber.Ctx) error {
	response := c.Locals(models.CurrentUser)
	return helper.NewResponse(fiber.StatusOK).SetData(response).WriteResponse(c)
}

func (q *accountController) UserChangePassword(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserChangePassword"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	request, statusCode, err := sanitizers.ValidateChangePassword(ctx, c)
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
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.accountService.UpdateUser(ctx, tx, currentUser); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountController) UserChangeUsername(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserChangeUsername"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	request, statusCode, err := sanitizers.ValidateChangeUsername(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateChangeUsername")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	encryptedPassword := helper.String2ByteSlice(*currentUser.EncryptedPassword)
	if !helper.MatchedHashAndPassword(encryptedPassword, helper.String2ByteSlice(request.Password)) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("password: invalid").WriteResponse(c)
	}
	if currentUser.Username == request.Username {
		return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
	}
	accounts, _, err := q.accountService.FindAccounts(
		ctx,
		models.NewAccountFilter(
			models.AccountWithUsername(request.Username),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) > 0 && accounts[0].ID != currentUser.ID {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("username already exists").WriteResponse(c)
	}
	now := time.Now()
	currentUser.Username = request.Username
	currentUser.UpdatedAt = now
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.accountService.UpdateUser(ctx, tx, currentUser); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountController) UserChangeEmail(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserChangeEmail"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	request, statusCode, err := sanitizers.ValidateChangeEmail(ctx, c)
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
	accounts, _, err := q.accountService.FindAccounts(
		ctx,
		models.NewAccountFilter(
			models.AccountWithEmail(request.Email),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) > 0 && accounts[0].ID != currentUser.ID {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("email already exists").WriteResponse(c)
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
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.accountService.UpdateUser(ctx, tx, currentUser); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountController) UserChangePhone(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-UserChangePhone"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	request, statusCode, err := sanitizers.ValidateChangePhone(ctx, c)
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
	accounts, _, err := q.accountService.FindAccounts(
		ctx,
		models.NewAccountFilter(
			models.AccountWithPhone(request.Phone),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) > 0 && accounts[0].ID != currentUser.ID {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("phone already exists").WriteResponse(c)
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
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.accountService.UpdateUser(ctx, tx, currentUser); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}

func (q *accountController) userNewLogin(c fiber.Ctx) error {
	flash := helper.NewFlashMessage()
	var request models.LoginRequest
	sess := session.FromContext(c)
	authenticated, ok := sess.Get(models.Authenticated).(bool)
	if ok && authenticated {
		return c.Redirect().To("/account/me")
	}
	return c.Render("account/login", fiber.Map{
		"authenticated": authenticated,
		"flash":         flash,
		"request":       request,
		"path":          c.Route().Path,
	})
}

func (q *accountController) userLogin(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-userLogin"
	flash := helper.NewFlashMessage()
	sess := session.FromContext(c)
	authenticated, ok := sess.Get(models.Authenticated).(bool)
	if ok && authenticated {
		return c.Redirect().To("/account/me")
	}
	request, statusCode, err := sanitizers.ValidateLogin(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateLogin")
		c.Response().SetStatusCode(statusCode)
		return c.Render("account/login", fiber.Map{
			"authenticated": authenticated,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"path":          c.Route().Path,
		})
	}
	users, _, err := q.accountService.FindUsers(
		ctx,
		models.NewAccountFilter(models.AccountWithLogin(request.Login)),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("account/login", fiber.Map{
			"authenticated": authenticated,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"path":          c.Route().Path,
		})
	}
	if len(users) == 0 ||
		users[0].Status != models.StatusConfirmed ||
		users[0].EncryptedPassword == nil {
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("account/login", fiber.Map{
			"authenticated": authenticated,
			"flash":         flash.Danger("login failed"),
			"request":       request,
			"path":          c.Route().Path,
		})
	}
	oldUser := users[0]
	if oldUser.LoginLockedAt != nil {
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("account/login", fiber.Map{
			"authenticated": authenticated,
			"flash":         flash.Danger("login locked out, max. failed attempts exceeded"),
			"request":       request,
			"path":          c.Route().Path,
		})
	}
	encryptedPassword := helper.String2ByteSlice(*oldUser.EncryptedPassword)
	now := time.Now()
	tx, err := repositories.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("account/login", fiber.Map{
			"authenticated": authenticated,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"path":          c.Route().Path,
		})
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
		if oldUser.LoginFailedAttempts++; oldUser.LoginFailedAttempts >= helper.GetLoginMaxFailedAttempts() {
			loginLockoutToken := helper.RandomString(32)
			oldUser.LoginLockedAt = &now
			oldUser.LoginUnlockToken = &loginLockoutToken
		}
		newUser, err := q.accountService.UpdateUser(ctx, tx, oldUser)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
			c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
			return c.Render("account/login", fiber.Map{
				"authenticated": authenticated,
				"flash":         flash.Danger(err.Error()),
				"request":       request,
				"path":          c.Route().Path,
			})
		}
		if newUser.LoginLockedAt != nil {
			if _, err = q.jwtService.DeleteJWTs(ctx, tx, models.NewJwtDeleteFilter(models.JwtWithDeleteAccountID(newUser.ID))); err != nil {
				helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
				c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
				return c.Render("account/login", fiber.Map{
					"authenticated": authenticated,
					"flash":         flash.Danger(err.Error()),
					"request":       request,
					"path":          c.Route().Path,
				})
			}
		}
		if err = tx.Commit(ctx); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
			c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
			return c.Render("account/login", fiber.Map{
				"authenticated": authenticated,
				"flash":         flash.Danger(err.Error()),
				"request":       request,
				"path":          c.Route().Path,
			})
		}
		if newUser.LoginLockedAt != nil {
			c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
			return c.Render("account/login", fiber.Map{
				"authenticated": authenticated,
				"flash":         flash.Danger("login locked out, max. failed attempts exceeded"),
				"request":       request,
				"path":          c.Route().Path,
			})
		}
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("account/login", fiber.Map{
			"authenticated": authenticated,
			"flash":         flash.Danger("login failed"),
			"request":       request,
			"path":          c.Route().Path,
		})
	}
	ipAddress := c.IP()
	oldUser.LoginCount++
	oldUser.LastLoginAt = oldUser.CurrentLoginAt
	oldUser.LastLoginIP = oldUser.CurrentLoginIP
	oldUser.CurrentLoginAt = &now
	oldUser.CurrentLoginIP = &ipAddress
	oldUser.LoginFailedAttempts = 0
	newUser, err := q.accountService.UpdateUser(ctx, tx, oldUser)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("account/login", fiber.Map{
			"authenticated": authenticated,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"path":          c.Route().Path,
		})
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("account/login", fiber.Map{
			"authenticated": authenticated,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"path":          c.Route().Path,
		})
	}
	if err = sess.Regenerate(); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrRegenerate")
	}
	sess.Set(models.Authenticated, true)
	sess.Set(models.UserID, newUser.ID)
	return flash.Redirect(c, sess.Session, "/account/me")
}

func (q *accountController) userLogout(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "AccountController-userLogout"
	flash := helper.NewFlashMessage()
	sess := session.FromContext(c)
	if err := sess.Reset(); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrReset")
	}
	return flash.Redirect(c, sess.Session, "/account/login")
}

func (q *accountController) userProfile(c fiber.Ctx) error {
	flash := helper.NewFlashMessage()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	return c.Render("account/me", fiber.Map{
		"authenticated": true,
		"flash":         flash,
		"currentUser":   currentUser,
		"cart":          cart,
		"path":          c.Route().Path,
	})
}
