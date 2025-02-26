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
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	companyModel "github.com/roysitumorang/sadia/modules/company/model"
	"github.com/roysitumorang/sadia/modules/company/sanitizer"
	companyUseCase "github.com/roysitumorang/sadia/modules/company/usecase"
	jwtModel "github.com/roysitumorang/sadia/modules/jwt/model"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	"go.uber.org/zap"
)

type (
	companyHTTPHandler struct {
		jwtUseCase     jwtUseCase.JwtUseCase
		accountUseCase accountUseCase.AccountUseCase
		companyUseCase companyUseCase.CompanyUseCase
	}
)

func New(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	companyUseCase companyUseCase.CompanyUseCase,
) *companyHTTPHandler {
	return &companyHTTPHandler{
		jwtUseCase:     jwtUseCase,
		accountUseCase: accountUseCase,
		companyUseCase: companyUseCase,
	}
}

func (q *companyHTTPHandler) Mount(r fiber.Router) {
	adminKeyAuth := middleware.AdminKeyAuth(q.jwtUseCase, q.accountUseCase)
	superAdminKeyAuth := middleware.AdminKeyAuth(q.jwtUseCase, q.accountUseCase, accountModel.AdminLevelSuperAdmin)
	admin := r.Group("/admin")
	admin.Get("", adminKeyAuth, q.AdminFindCompanies).
		Post("", superAdminKeyAuth, q.AdminCreateCompany).
		Get("/:id", adminKeyAuth, q.AdminFindCompanyByID).
		Delete("/:id", superAdminKeyAuth, q.AdminDeactivateCompany)
	userKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase)
	ownerKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase, accountModel.UserLevelOwner)
	r.Group("/mine").
		Get("", userKeyAuth, q.UserFindMyCompany).
		Put("", ownerKeyAuth, q.UserUpdateMyCompany)
}

func (q *companyHTTPHandler) AdminFindCompanies(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "CompanyPresenter-AdminFindCompanies"
	filter, err := sanitizer.FindCompanies(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindCompanies")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	rows, pagination, err := q.companyUseCase.FindCompanies(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindCompanies")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *companyHTTPHandler) AdminCreateCompany(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "CompanyPresenter-AdminCreateCompany"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*accountModel.Admin)
	request, statusCode, err := sanitizer.ValidateCompany(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateCompany")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	request.CreatedBy = currentAdmin.ID
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
	response, err := q.companyUseCase.CreateCompany(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateCompany")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	user := accountModel.NewUser{
		NewAccount: request.Owner,
		CompanyID:  response.ID,
		UserLevel:  accountModel.UserLevelOwner,
	}
	if _, err = q.accountUseCase.CreateUser(ctx, tx, &user); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *companyHTTPHandler) AdminFindCompanyByID(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "CompanyPresenter-AdminFindCompanyByID"
	companies, _, err := q.companyUseCase.FindCompanies(ctx, companyModel.NewFilter(companyModel.WithCompanyIDs(c.Params("id"))))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindCompanies")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(companies) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("company not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(companies[0]).WriteResponse(c)
}

func (q *companyHTTPHandler) AdminDeactivateCompany(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "CompanyPresenter-AdminDeactivateCompany"
	currentAdmin, _ := c.Locals(models.CurrentAdmin).(*accountModel.Admin)
	request, statusCode, err := sanitizer.ValidateDeactivation(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateDeactivation")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	companies, _, err := q.companyUseCase.FindCompanies(
		ctx,
		companyModel.NewFilter(companyModel.WithCompanyIDs(c.Params("id"))),
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
	if err = q.companyUseCase.UpdateCompany(ctx, tx, company); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if _, err = q.jwtUseCase.DeleteJWTs(ctx, tx, jwtModel.NewDeleteFilter(jwtModel.WithCompanyID(company.ID))); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(company).WriteResponse(c)
}

func (q *companyHTTPHandler) UserFindMyCompany(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "CompanyPresenter-UserFindMyCompany"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	companies, _, err := q.companyUseCase.FindCompanies(
		ctx,
		companyModel.NewFilter(companyModel.WithCompanyIDs(currentUser.CompanyID)),
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

func (q *companyHTTPHandler) UserUpdateMyCompany(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "CompanyPresenter-UserUpdateMyCompany"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	request, statusCode, err := sanitizer.ValidateUpdateCompany(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateUpdateCompany")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	companies, _, err := q.companyUseCase.FindCompanies(
		ctx,
		companyModel.NewFilter(companyModel.WithCompanyIDs(currentUser.CompanyID)),
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
	if err = q.companyUseCase.UpdateCompany(ctx, tx, company); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(company).WriteResponse(c)
}
