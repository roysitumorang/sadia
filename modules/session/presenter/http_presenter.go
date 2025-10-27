package presenter

import (
	"errors"
	"fmt"
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
	userKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase, q.companyUseCase, q.sessionUseCase)
	v1 := r.Group("/v1")
	v1.Get("", userKeyAuth, q.UserFindSessions).
		Post("", userKeyAuth, q.UserCreateSession).
		Get("/mine", userKeyAuth, q.UserFindCurrentSession).
		Put("/mine", userKeyAuth, q.UserCloseCurrentSession)
	userSessionAuth := middleware.UserSessionAuth(q.sessionStore, q.accountUseCase, q.companyUseCase, q.sessionUseCase)
	r.Get("", userSessionAuth, q.userIndex).
		Get("/new", userSessionAuth, q.userNew).
		Post("", userSessionAuth, q.userCreate).
		Get("/:id", userSessionAuth, q.userShow).
		Post("/:id/spending", userSessionAuth, q.userCreateSpending).
		Post("/:id", userSessionAuth, q.userClose)
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
	currentCompany, _ := c.Locals(models.CurrentCompany).(*companyModel.Company)
	if currentCompany.SessionID != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("close user current session before starting new session").WriteResponse(c)
	}
	request, statusCode, err := sanitizer.ValidateSession(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateSession")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
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
	currentCompany.SessionID = &response.ID
	if err = q.companyUseCase.UpdateCompany(ctx, tx, currentCompany); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *sessionHTTPHandler) UserFindCurrentSession(c *fiber.Ctx) error {
	currentCompany, _ := c.Locals(models.CurrentCompany).(*companyModel.Company)
	if currentCompany.SessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active session").WriteResponse(c)
	}
	currentSession := c.Locals(models.CurrentSession).(*sessionModel.Session)
	return helper.NewResponse(fiber.StatusOK).SetData(currentSession).WriteResponse(c)
}

func (q *sessionHTTPHandler) UserCloseCurrentSession(c *fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "SessionPresenter-UserCloseCurrentSession"
	currentCompany, _ := c.Locals(models.CurrentCompany).(*companyModel.Company)
	if currentCompany.SessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active session").WriteResponse(c)
	}
	currentSession := c.Locals(models.CurrentSession).(*sessionModel.Session)
	now := time.Now()
	currentSession.Status = sessionModel.StatusClosed
	currentSession.ClosedAt = &now
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
	if err = q.sessionUseCase.UpdateSession(ctx, tx, currentSession); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateSession")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	currentCompany.SessionID = nil
	if err = q.companyUseCase.UpdateCompany(ctx, tx, currentCompany); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(currentSession).WriteResponse(c)
}

func (q *sessionHTTPHandler) userIndex(c *fiber.Ctx) error {
	ctxt := "SessionPresenter-userIndex"
	ctx := c.Context()
	sess, err := q.sessionStore.Get(c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGet")
		return c.Render("account/login", fiber.Map{
			"authenticated": false,
			"flash":         helper.NewFlashMessage().Danger(err.Error()),
			"request":       accountModel.LoginRequest{},
		})
	}
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	currentCompany := sess.Get(models.CurrentCompany).(*companyModel.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	pagination := new(models.Pagination)
	var rows []*sessionModel.Session
	filter, err := sanitizer.FindSessions(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindSessions")
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("session/index", fiber.Map{
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash,
			"q":              c.Query("q"),
			"rows":           rows,
			"pagination":     pagination,
			"limits":         models.Limits,
			"currentCompany": currentCompany,
		})
	}
	filter.CompanyIDs = []string{currentUser.CompanyID}
	if rows, pagination, err = q.sessionUseCase.FindSessions(ctx, filter); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindSessions")
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("session/index", fiber.Map{
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash,
			"q":              c.Query("q"),
			"rows":           rows,
			"pagination":     pagination,
			"limits":         models.Limits,
			"currentCompany": currentCompany,
		})
	}
	defer flash.Clear(c, sess)
	return c.Render("session/index", fiber.Map{
		"authenticated":  true,
		"currentUser":    currentUser,
		"flash":          flash,
		"q":              c.Query("q"),
		"rows":           rows,
		"pagination":     pagination,
		"limits":         models.Limits,
		"currentCompany": currentCompany,
	})
}

func (q *sessionHTTPHandler) userNew(c *fiber.Ctx) error {
	ctxt := "SessionPresenter-userNew"
	ctx := c.Context()
	sess, err := q.sessionStore.Get(c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGet")
		return c.Render("account/login", fiber.Map{
			"authenticated": false,
			"flash":         helper.NewFlashMessage().Danger(err.Error()),
			"request":       accountModel.LoginRequest{},
		})
	}
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	currentCompany := sess.Get(models.CurrentCompany).(*companyModel.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	if currentCompany.SessionID != nil {
		return c.Redirect("/session")
	}
	request := new(sessionModel.Session)
	defer flash.Clear(c, sess)
	return c.Render("session/new", fiber.Map{
		"authenticated": true,
		"currentUser":   currentUser,
		"flash":         flash,
		"request":       request,
	})
}

func (q *sessionHTTPHandler) userCreate(c *fiber.Ctx) error {
	ctxt := "SessionPresenter-userCreate"
	ctx := c.Context()
	sess, err := q.sessionStore.Get(c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGet")
		return c.Render("account/login", fiber.Map{
			"authenticated": false,
			"flash":         helper.NewFlashMessage().Danger(err.Error()),
			"request":       accountModel.LoginRequest{},
		})
	}
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	currentCompany := sess.Get(models.CurrentCompany).(*companyModel.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	if currentCompany.SessionID != nil {
		return c.Redirect("/session")
	}
	request, statusCode, err := sanitizer.ValidateSession(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateSession")
		c.Response().SetStatusCode(statusCode)
		return c.Render("session/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
		})
	}
	request.CompanyID = currentUser.CompanyID
	request.CreatedBy = currentUser.ID
	tx, err := helper.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
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
	response, err := q.sessionUseCase.CreateSession(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateSession")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
		})
	}
	currentCompany.SessionID = &response.ID
	if err = q.companyUseCase.UpdateCompany(ctx, tx, currentCompany); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
		})
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
		})
	}
	return flash.Success("session created successfully").Redirect(c, sess, "/session")
}

func (q *sessionHTTPHandler) userShow(c *fiber.Ctx) error {
	ctxt := "SessionPresenter-userShow"
	ctx := c.Context()
	sess, err := q.sessionStore.Get(c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGet")
		return c.Render("account/login", fiber.Map{
			"authenticated": false,
			"flash":         helper.NewFlashMessage().Danger(err.Error()),
			"request":       accountModel.LoginRequest{},
		})
	}
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	currentCompany := sess.Get(models.CurrentCompany).(*companyModel.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	session := new(sessionModel.Session)
	request := new(sessionModel.Spending)
	sessions, _, err := q.sessionUseCase.FindSessions(
		ctx,
		sessionModel.NewFilter(
			sessionModel.WithCompanyIDs(currentUser.CompanyID),
			sessionModel.WithSessionIDs(c.Params("id")),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindSessions")
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("session/show", fiber.Map{
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash.Danger(err.Error()),
			"currentCompany": currentCompany,
			"session":        session,
			"request":        request,
		})
	}
	if len(sessions) == 0 {
		return flash.Danger("session not found").Redirect(c, sess, "/session")
	}
	session = sessions[0]
	defer flash.Clear(c, sess)
	return c.Render("session/show", fiber.Map{
		"authenticated":  true,
		"currentUser":    currentUser,
		"flash":          flash,
		"currentCompany": currentCompany,
		"session":        session,
		"request":        request,
	})
}

func (q *sessionHTTPHandler) userCreateSpending(c *fiber.Ctx) error {
	ctxt := "SessionPresenter-userCreateSpending"
	ctx := c.Context()
	sess, err := q.sessionStore.Get(c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGet")
		return c.Render("account/login", fiber.Map{
			"authenticated": false,
			"flash":         helper.NewFlashMessage().Danger(err.Error()),
			"request":       accountModel.LoginRequest{},
		})
	}
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	currentCompany := sess.Get(models.CurrentCompany).(*companyModel.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	if currentCompany.SessionID == nil {
		return c.Redirect("/session")
	}
	currentSession := sess.Get(models.CurrentSession).(*sessionModel.Session)
	request, statusCode, err := sanitizer.ValidateSpending(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateSpending")
		c.Response().SetStatusCode(statusCode)
		return c.Render("session/show", fiber.Map{
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash.Danger(err.Error()),
			"currentCompany": currentCompany,
			"session":        currentSession,
			"request":        request,
		})
	}
	request.SessionID = *currentCompany.SessionID
	request.CreatedBy = currentUser.ID
	tx, err := helper.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/show", fiber.Map{
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash.Danger(err.Error()),
			"currentCompany": currentCompany,
			"session":        currentSession,
			"request":        request,
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
	if err = q.sessionUseCase.CreateSpending(ctx, tx, request); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateSpending")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/show", fiber.Map{
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash.Danger(err.Error()),
			"currentCompany": currentCompany,
			"session":        currentSession,
			"request":        request,
		})
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/show", fiber.Map{
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash.Danger(err.Error()),
			"currentCompany": currentCompany,
			"session":        currentSession,
			"request":        request,
		})
	}
	return flash.Success("spending created successfully").Redirect(c, sess, fmt.Sprintf("/session/%s", currentSession.ID))
}

func (q *sessionHTTPHandler) userClose(c *fiber.Ctx) error {
	ctxt := "SessionPresenter-userClose"
	ctx := c.Context()
	sess, err := q.sessionStore.Get(c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGet")
		return c.Render("account/login", fiber.Map{
			"authenticated": false,
			"flash":         helper.NewFlashMessage().Danger(err.Error()),
			"request":       accountModel.LoginRequest{},
		})
	}
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	currentCompany := sess.Get(models.CurrentCompany).(*companyModel.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	if currentCompany.SessionID == nil {
		return c.Redirect("/session")
	}
	currentSession := sess.Get(models.CurrentSession).(*sessionModel.Session)
	now := time.Now()
	currentSession.Status = sessionModel.StatusClosed
	currentSession.ClosedBy = &currentUser.ID
	currentSession.ClosedAt = &now
	tx, err := helper.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/show", fiber.Map{
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash,
			"currentCompany": currentCompany,
			"session":        currentSession,
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
	if err = q.sessionUseCase.UpdateSession(ctx, tx, currentSession); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateSession")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/show", fiber.Map{
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash,
			"currentCompany": currentCompany,
			"session":        currentSession,
		})
	}
	currentCompany.SessionID = nil
	if err = q.companyUseCase.UpdateCompany(ctx, tx, currentCompany); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/show", fiber.Map{
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash,
			"currentCompany": currentCompany,
			"session":        currentSession,
		})
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/show", fiber.Map{
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash,
			"currentCompany": currentCompany,
			"session":        currentSession,
		})
	}
	return flash.Success("session closed successfully").Redirect(c, sess, "/session")
}
