package controllers

import (
	"errors"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/repositories"
	"github.com/roysitumorang/sadia/sanitizers"
	"github.com/roysitumorang/sadia/services"
	"go.uber.org/zap"
)

type companyController struct {
	jwtService     services.JwtService
	accountService services.AccountService
	companyService services.CompanyService
	sessionService services.SessionService
}

func NewCompanyController(
	jwtService services.JwtService,
	accountService services.AccountService,
	companyService services.CompanyService,
	sessionService services.SessionService,
) *companyController {
	return &companyController{
		jwtService:     jwtService,
		accountService: accountService,
		companyService: companyService,
		sessionService: sessionService,
	}
}

func (q *companyController) Mount(r fiber.Router) {
	adminKeyAuth := middleware.AdminKeyAuth(q.jwtService, q.accountService)
	superAdminKeyAuth := middleware.AdminKeyAuth(q.jwtService, q.accountService, models.AdminLevelSuperAdmin)
	v1 := r.Group("/v1")
	admin := v1.Group("/admin")
	admin.Get("", adminKeyAuth, q.AdminFindCompanies).
		Post("", superAdminKeyAuth, q.AdminCreateCompany).
		Get("/:id", adminKeyAuth, q.AdminFindCompanyByID).
		Delete("/:id", superAdminKeyAuth, q.AdminDeactivateCompany)
	userKeyAuth := middleware.UserKeyAuth(q.jwtService, q.accountService, q.companyService, q.sessionService)
	ownerKeyAuth := middleware.UserKeyAuth(q.jwtService, q.accountService, q.companyService, q.sessionService, models.UserLevelOwner)
	v1.Group("/mine").
		Get("", userKeyAuth, q.UserFindMyCompany).
		Put("", ownerKeyAuth, q.UserUpdateMyCompany)
}

func (q *companyController) AdminFindCompanies(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "CompanyController-AdminFindCompanies"
	filter, err := sanitizers.FindCompanies(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindCompanies")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	rows, pagination, err := q.companyService.FindCompanies(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindCompanies")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *companyController) AdminCreateCompany(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "CompanyController-AdminCreateCompany"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*models.Admin)
	request, statusCode, err := sanitizers.ValidateCompany(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateCompany")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	request.CreatedBy = currentAdmin.ID
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
	response, err := q.companyService.CreateCompany(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateCompany")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	user := models.NewUser{
		NewAccount: request.Owner,
		CompanyID:  response.ID,
		UserLevel:  models.UserLevelOwner,
	}
	if _, err = q.accountService.CreateUser(ctx, tx, &user); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *companyController) AdminFindCompanyByID(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "CompanyController-AdminFindCompanyByID"
	companyID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("company not found").WriteResponse(c)
	}
	companies, _, err := q.companyService.FindCompanies(ctx, models.NewCompanyFilter(models.CompanyWithCompanyIDs(companyID)))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindCompanies")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(companies) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("company not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(companies[0]).WriteResponse(c)
}

func (q *companyController) AdminDeactivateCompany(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "CompanyController-AdminDeactivateCompany"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*models.Admin)
	companyID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("company not found").WriteResponse(c)
	}
	request, statusCode, err := sanitizers.ValidateCompanyDeactivation(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateCompanyDeactivation")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	companies, _, err := q.companyService.FindCompanies(
		ctx,
		models.NewCompanyFilter(models.CompanyWithCompanyIDs(companyID)),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindCompanies")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(companies) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("company not found").WriteResponse(c)
	}
	company := companies[0]
	if company.Status != models.StatusConfirmed {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("cannot deactivate unconfirmed & deactivated company").WriteResponse(c)
	}
	now := time.Now()
	company.Status = models.StatusDeactivated
	company.DeactivatedBy = &currentAdmin.ID
	company.DeactivatedAt = &now
	company.DeactivationReason = &request.Reason
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
	if err = q.companyService.UpdateCompany(ctx, tx, company); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if _, err = q.jwtService.DeleteJWTs(ctx, tx, models.NewJwtDeleteFilter(models.JwtWithDeleteCompanyID(company.ID))); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(company).WriteResponse(c)
}

func (q *companyController) UserFindMyCompany(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "CompanyController-UserFindMyCompany"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	companies, _, err := q.companyService.FindCompanies(
		ctx,
		models.NewCompanyFilter(models.CompanyWithCompanyIDs(currentUser.CompanyID)),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindCompanies")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(companies) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("company not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(companies[0]).WriteResponse(c)
}

func (q *companyController) UserUpdateMyCompany(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "CompanyController-UserUpdateMyCompany"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	request, statusCode, err := sanitizers.ValidateUpdateCompany(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateUpdateCompany")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	companies, _, err := q.companyService.FindCompanies(
		ctx,
		models.NewCompanyFilter(models.CompanyWithCompanyIDs(currentUser.CompanyID)),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindCompanies")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(companies) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("company not found").WriteResponse(c)
	}
	company := companies[0]
	now := time.Now()
	company.Name = request.Name
	company.Slug = request.Slug
	company.UpdatedBy = currentUser.ID
	company.UpdatedAt = now
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
	if err = q.companyService.UpdateCompany(ctx, tx, company); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(company).WriteResponse(c)
}
