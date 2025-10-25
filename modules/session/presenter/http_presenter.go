package presenter

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	companyModel "github.com/roysitumorang/sadia/modules/company/model"
	companyUseCase "github.com/roysitumorang/sadia/modules/company/usecase"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	sessionModel "github.com/roysitumorang/sadia/modules/session/model"
	"github.com/roysitumorang/sadia/modules/session/sanitizer"
	sessionUseCase "github.com/roysitumorang/sadia/modules/session/usecase"
	"go.uber.org/zap"
)

type (
	sessionHTTPHandler struct {
		sessionStore   *session.Store
		jwtUseCase     jwtUseCase.JwtUseCase
		accountUseCase accountUseCase.AccountUseCase
		companyUseCase companyUseCase.CompanyUseCase
		sessionUseCase sessionUseCase.SessionUseCase
	}
)

func New(
	sessionStore *session.Store,
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	companyUseCase companyUseCase.CompanyUseCase,
	sessionUseCase sessionUseCase.SessionUseCase,
) *sessionHTTPHandler {
	return &sessionHTTPHandler{
		sessionStore:   sessionStore,
		jwtUseCase:     jwtUseCase,
		accountUseCase: accountUseCase,
		companyUseCase: companyUseCase,
		sessionUseCase: sessionUseCase,
	}
}

func (q *sessionHTTPHandler) Mount(r fiber.Router) {
	userKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase)
	v1 := r.Group("/v1")
	v1.Get("", userKeyAuth, q.UserFindSessions).
		Post("", userKeyAuth, q.UserCreateSession).
		Get("/mine", userKeyAuth, q.UserFindCurrentSession).
		Put("/mine", userKeyAuth, q.UserCloseCurrentSession)
}

func (q *sessionHTTPHandler) UserFindSessions(c *fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "SessionPresenter-UserFindSessions"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	filter, err := sanitizer.FindSessions(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindSessions")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	filter.CompanyIDs = []string{currentUser.CompanyID}
	rows, pagination, err := q.sessionUseCase.FindSessions(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindSessions")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *sessionHTTPHandler) UserCreateSession(c *fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "SessionPresenter-UserCreateSession"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	if currentUser.CurrentSessionID != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("close user current session before starting new session").WriteResponse(c)
	}
	request, statusCode, err := sanitizer.ValidateNewSession(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateNewSession")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	companies, _, err := q.companyUseCase.FindCompanies(ctx, companyModel.NewFilter(companyModel.WithCompanyIDs(currentUser.CompanyID)))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindCompanies")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(companies) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("company not found").WriteResponse(c)
	}
	company := companies[0]
	if company.SessionID != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("close company current session before starting new session").WriteResponse(c)
	}
	request.CreatedBy = currentUser.ID
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
	response, err := q.sessionUseCase.CreateSession(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateSession")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	company.SessionID = &response.ID
	if err = q.companyUseCase.UpdateCompany(ctx, tx, company); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	currentUser.CurrentSessionID = &response.ID
	if err = q.accountUseCase.UpdateUser(ctx, tx, currentUser); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *sessionHTTPHandler) UserFindCurrentSession(c *fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "SessionPresenter-UserFindCurrentSession"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	if currentUser.CurrentSessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active session").WriteResponse(c)
	}
	sessions, _, err := q.sessionUseCase.FindSessions(
		ctx,
		sessionModel.NewFilter(
			sessionModel.WithSessionIDs(*currentUser.CurrentSessionID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindSessions")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(sessions) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("session not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(sessions[0]).WriteResponse(c)
}

func (q *sessionHTTPHandler) UserCloseCurrentSession(c *fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "SessionPresenter-UserCloseCurrentSession"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	if currentUser.CurrentSessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active session").WriteResponse(c)
	}
	request, statusCode, err := sanitizer.ValidateCloseSession(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateCloseSession")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	sessions, _, err := q.sessionUseCase.FindSessions(
		ctx,
		sessionModel.NewFilter(
			sessionModel.WithSessionIDs(*currentUser.CurrentSessionID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindSessions")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(sessions) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("session not found").WriteResponse(c)
	}
	session := sessions[0]
	companies, _, err := q.companyUseCase.FindCompanies(ctx, companyModel.NewFilter(companyModel.WithCompanyIDs(currentUser.CompanyID)))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindCompanies")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(companies) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("company not found").WriteResponse(c)
	}
	company := companies[0]
	now := time.Now()
	session.Status = sessionModel.StatusClosed
	session.SpendingValue = request.SpendingValue
	session.ClosedAt = &now
	session.SpendingLineItems = make([]*sessionModel.SpendingLineItem, len(request.SpendingLineItems))
	for i, lineItem := range request.SpendingLineItems {
		session.SpendingLineItems[i] = &sessionModel.SpendingLineItem{
			Description: lineItem.Description,
			Value:       lineItem.Value,
		}
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
	if err = q.sessionUseCase.UpdateSession(ctx, tx, session); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateSession")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	company.SessionID = nil
	if err = q.companyUseCase.UpdateCompany(ctx, tx, company); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	currentUser.CurrentSessionID = nil
	if err = q.accountUseCase.UpdateUser(ctx, tx, currentUser); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(session).WriteResponse(c)
}
