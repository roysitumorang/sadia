package controllers

import (
	"errors"
	"fmt"
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

type sessionController struct {
	jwtService     services.JwtService
	accountService services.AccountService
	companyService services.CompanyService
	sessionService services.SessionService
}

func NewSessionController(
	jwtService services.JwtService,
	accountService services.AccountService,
	companyService services.CompanyService,
	sessionService services.SessionService,
) *sessionController {
	return &sessionController{
		jwtService:     jwtService,
		accountService: accountService,
		companyService: companyService,
		sessionService: sessionService,
	}
}

func (q *sessionController) Mount(r fiber.Router) {
	userKeyAuth := middleware.UserKeyAuth(q.jwtService, q.accountService, q.companyService, q.sessionService)
	v1 := r.Group("/v1")
	v1.Get("", userKeyAuth, q.UserFindSessions).
		Post("", userKeyAuth, q.UserCreateSession).
		Get("/mine", userKeyAuth, q.UserFindCurrentSession).
		Put("/mine", userKeyAuth, q.UserCloseCurrentSession)
	userSessionAuth := middleware.UserSessionAuth(q.accountService, q.companyService, q.sessionService)
	r.Get("", userSessionAuth, q.userIndex).
		Get("/new", userSessionAuth, q.userNew).
		Post("", userSessionAuth, q.userCreate).
		Get("/:id", userSessionAuth, q.userShow).
		Post("/:id/spending", userSessionAuth, q.userCreateSpending).
		Post("/:id", userSessionAuth, q.userClose)
}

func (q *sessionController) UserFindSessions(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "SessionPresenter-UserFindSessions"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	filter, err := sanitizers.FindSessions(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindSessions")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	filter.CompanyIDs = []uint64{currentUser.CompanyID}
	rows, pagination, err := q.sessionService.FindSessions(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindSessions")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *sessionController) UserCreateSession(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "SessionPresenter-UserCreateSession"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	currentCompany, _ := c.Locals(models.CurrentCompany).(*models.Company)
	if currentCompany.SessionID != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("close user current session before starting new session").WriteResponse(c)
	}
	request, statusCode, err := sanitizers.ValidateSession(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateSession")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	request.CreatedBy = currentUser.ID
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
	response, err := q.sessionService.CreateSession(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateSession")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	currentCompany.SessionID = &response.ID
	if err = q.companyService.UpdateCompany(ctx, tx, currentCompany); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *sessionController) UserFindCurrentSession(c fiber.Ctx) error {
	currentCompany, _ := c.Locals(models.CurrentCompany).(*models.Company)
	if currentCompany.SessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active session").WriteResponse(c)
	}
	currentSession := c.Locals(models.CurrentSession).(*models.Session)
	return helper.NewResponse(fiber.StatusOK).SetData(currentSession).WriteResponse(c)
}

func (q *sessionController) UserCloseCurrentSession(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "SessionPresenter-UserCloseCurrentSession"
	currentCompany, _ := c.Locals(models.CurrentCompany).(*models.Company)
	if currentCompany.SessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active session").WriteResponse(c)
	}
	currentSession := c.Locals(models.CurrentSession).(*models.Session)
	now := time.Now()
	currentSession.Status = models.StatusClosed
	currentSession.ClosedAt = &now
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
	if err = q.sessionService.UpdateSession(ctx, tx, currentSession); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateSession")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	currentCompany.SessionID = nil
	if err = q.companyService.UpdateCompany(ctx, tx, currentCompany); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(currentSession).WriteResponse(c)
}

func (q *sessionController) userIndex(c fiber.Ctx) error {
	ctxt := "SessionPresenter-userIndex"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	currentCompany := sess.Get(models.CurrentCompany).(*models.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	pagination := new(models.Pagination)
	var rows []*models.Session
	filter, err := sanitizers.FindSessions(ctx, c)
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
			"cart":           cart,
			"path":           c.Route().Path,
		})
	}
	filter.CompanyIDs = []uint64{currentUser.CompanyID}
	if rows, pagination, err = q.sessionService.FindSessions(ctx, filter); err != nil {
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
			"cart":           cart,
			"path":           c.Route().Path,
		})
	}
	defer flash.Clear(c, sess.Session)
	return c.Render("session/index", fiber.Map{
		"authenticated":  true,
		"currentUser":    currentUser,
		"flash":          flash,
		"q":              c.Query("q"),
		"rows":           rows,
		"pagination":     pagination,
		"limits":         models.Limits,
		"currentCompany": currentCompany,
		"cart":           cart,
		"path":           c.Route().Path,
	})
}

func (q *sessionController) userNew(c fiber.Ctx) error {
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	currentCompany := sess.Get(models.CurrentCompany).(*models.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	if currentCompany.SessionID != nil {
		return c.Redirect().To("/session")
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	request := new(models.Session)
	defer flash.Clear(c, sess.Session)
	return c.Render("session/new", fiber.Map{
		"authenticated": true,
		"currentUser":   currentUser,
		"flash":         flash,
		"request":       request,
		"cart":          cart,
		"path":          c.Route().Path,
	})
}

func (q *sessionController) userCreate(c fiber.Ctx) error {
	ctxt := "SessionPresenter-userCreate"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	currentCompany := sess.Get(models.CurrentCompany).(*models.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	if currentCompany.SessionID != nil {
		return c.Redirect().To("/session")
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	request, statusCode, err := sanitizers.ValidateSession(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateSession")
		c.Response().SetStatusCode(statusCode)
		return c.Render("session/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"cart":          cart,
			"path":          c.Route().Path,
		})
	}
	request.CompanyID = currentUser.CompanyID
	request.CreatedBy = currentUser.ID
	tx, err := repositories.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"cart":          cart,
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
	response, err := q.sessionService.CreateSession(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateSession")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"cart":          cart,
			"path":          c.Route().Path,
		})
	}
	currentCompany.SessionID = &response.ID
	if err = q.companyService.UpdateCompany(ctx, tx, currentCompany); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"cart":          cart,
			"path":          c.Route().Path,
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
			"cart":          cart,
			"path":          c.Route().Path,
		})
	}
	return flash.Success("session created successfully").Redirect(c, sess.Session, "/session")
}

func (q *sessionController) userShow(c fiber.Ctx) error {
	ctxt := "SessionPresenter-userShow"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	currentCompany := sess.Get(models.CurrentCompany).(*models.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	sessionID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return flash.Danger("session not found").Redirect(c, sess.Session, "/session")
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	session := new(models.Session)
	request := new(models.Spending)
	sessions, _, err := q.sessionService.FindSessions(
		ctx,
		models.NewSessionFilter(
			models.SessionWithCompanyIDs(currentUser.CompanyID),
			models.SessionWithSessionIDs(sessionID),
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
			"cart":           cart,
			"path":           c.Route().Path,
		})
	}
	if len(sessions) == 0 {
		return flash.Danger("session not found").Redirect(c, sess.Session, "/session")
	}
	session = sessions[0]
	defer flash.Clear(c, sess.Session)
	return c.Render("session/show", fiber.Map{
		"authenticated":  true,
		"currentUser":    currentUser,
		"flash":          flash,
		"currentCompany": currentCompany,
		"session":        session,
		"request":        request,
		"cart":           cart,
		"path":           c.Route().Path,
	})
}

func (q *sessionController) userCreateSpending(c fiber.Ctx) error {
	ctxt := "SessionPresenter-userCreateSpending"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	currentCompany := sess.Get(models.CurrentCompany).(*models.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	if currentCompany.SessionID == nil {
		return c.Redirect().To("/session")
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	currentSession := sess.Get(models.CurrentSession).(*models.Session)
	request, statusCode, err := sanitizers.ValidateSpending(ctx, c)
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
			"cart":           cart,
			"path":           c.Route().Path,
		})
	}
	request.SessionID = *currentCompany.SessionID
	request.CreatedBy = currentUser.ID
	tx, err := repositories.BeginTx(ctx)
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
			"cart":           cart,
			"path":           c.Route().Path,
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
	if err = q.sessionService.CreateSpending(ctx, tx, request); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateSpending")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/show", fiber.Map{
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash.Danger(err.Error()),
			"currentCompany": currentCompany,
			"session":        currentSession,
			"request":        request,
			"cart":           cart,
			"path":           c.Route().Path,
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
			"cart":           cart,
			"path":           c.Route().Path,
		})
	}
	return flash.Success("spending created successfully").Redirect(c, sess.Session, fmt.Sprintf("/session/%d", currentSession.ID))
}

func (q *sessionController) userClose(c fiber.Ctx) error {
	ctxt := "SessionPresenter-userClose"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	currentCompany := sess.Get(models.CurrentCompany).(*models.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	if currentCompany.SessionID == nil {
		return c.Redirect().To("/session")
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	currentSession := sess.Get(models.CurrentSession).(*models.Session)
	now := time.Now()
	currentSession.Status = models.StatusClosed
	currentSession.ClosedBy = &currentUser.ID
	currentSession.ClosedAt = &now
	tx, err := repositories.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/show", fiber.Map{
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash,
			"currentCompany": currentCompany,
			"session":        currentSession,
			"cart":           cart,
			"path":           c.Route().Path,
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
	if err = q.sessionService.UpdateSession(ctx, tx, currentSession); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateSession")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/show", fiber.Map{
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash,
			"currentCompany": currentCompany,
			"session":        currentSession,
			"cart":           cart,
			"path":           c.Route().Path,
		})
	}
	currentCompany.SessionID = nil
	if err = q.companyService.UpdateCompany(ctx, tx, currentCompany); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("session/show", fiber.Map{
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash,
			"currentCompany": currentCompany,
			"session":        currentSession,
			"cart":           cart,
			"path":           c.Route().Path,
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
			"cart":           cart,
			"path":           c.Route().Path,
		})
	}
	return flash.Success("session closed successfully").Redirect(c, sess.Session, "/session")
}
