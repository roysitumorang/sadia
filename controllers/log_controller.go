package controllers

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/sanitizers"
	"github.com/roysitumorang/sadia/services"
	"go.uber.org/zap"
)

type logController struct {
	jwtService     services.JwtService
	accountService services.AccountService
	companyService services.CompanyService
	sessionService services.SessionService
	logService     services.LogService
}

func NewLogController(
	jwtService services.JwtService,
	accountService services.AccountService,
	companyService services.CompanyService,
	sessionService services.SessionService,
	logService services.LogService,
) *logController {
	return &logController{
		jwtService:     jwtService,
		accountService: accountService,
		companyService: companyService,
		sessionService: sessionService,
		logService:     logService,
	}
}

func (q *logController) Mount(r fiber.Router) {
	userSessionAuth := middleware.UserSessionAuth(q.accountService, q.companyService, q.sessionService)
	r.Get("", userSessionAuth, q.userIndex)
}

func (q *logController) userIndex(c fiber.Ctx) error {
	ctxt := "LogController-userIndex"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	pagination := new(models.Pagination)
	var rows []*models.Log
	filter, err := sanitizers.FindLogs(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindLogs")
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("log/index", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"q":             c.Query("q"),
			"rows":          rows,
			"pagination":    pagination,
			"limits":        models.Limits,
			"cart":          cart,
		})
	}
	filter.CompanyIDs = []uint64{currentUser.CompanyID}
	if rows, pagination, err = q.logService.FindLogs(ctx, filter); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindLogs")
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("log/index", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"q":             c.Query("q"),
			"rows":          rows,
			"pagination":    pagination,
			"limits":        models.Limits,
			"cart":          cart,
		})
	}
	defer flash.Clear(c, sess.Session)
	return c.Render("log/index", fiber.Map{
		"authenticated": true,
		"currentUser":   currentUser,
		"flash":         flash,
		"q":             c.Query("q"),
		"rows":          rows,
		"pagination":    pagination,
		"limits":        models.Limits,
		"cart":          cart,
	})
}
