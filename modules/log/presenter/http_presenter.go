package presenter

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	companyUseCase "github.com/roysitumorang/sadia/modules/company/usecase"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	logModel "github.com/roysitumorang/sadia/modules/log/model"
	"github.com/roysitumorang/sadia/modules/log/sanitizer"
	logUseCase "github.com/roysitumorang/sadia/modules/log/usecase"
	sessionUseCase "github.com/roysitumorang/sadia/modules/session/usecase"
	transactionModel "github.com/roysitumorang/sadia/modules/transaction/model"
	"go.uber.org/zap"
)

type (
	logHTTPHandler struct {
		jwtUseCase     jwtUseCase.JwtUseCase
		accountUseCase accountUseCase.AccountUseCase
		companyUseCase companyUseCase.CompanyUseCase
		sessionUseCase sessionUseCase.SessionUseCase
		logUseCase     logUseCase.LogUseCase
	}
)

func New(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	companyUseCase companyUseCase.CompanyUseCase,
	sessionUseCase sessionUseCase.SessionUseCase,
	logUseCase logUseCase.LogUseCase,
) *logHTTPHandler {
	return &logHTTPHandler{
		jwtUseCase:     jwtUseCase,
		accountUseCase: accountUseCase,
		companyUseCase: companyUseCase,
		sessionUseCase: sessionUseCase,
		logUseCase:     logUseCase,
	}
}

func (q *logHTTPHandler) Mount(r fiber.Router) {
	userSessionAuth := middleware.UserSessionAuth(q.accountUseCase, q.companyUseCase, q.sessionUseCase)
	r.Get("", userSessionAuth, q.userIndex)
}

func (q *logHTTPHandler) userIndex(c fiber.Ctx) error {
	ctxt := "LogPresenter-userIndex"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	pagination := new(models.Pagination)
	var rows []*logModel.Log
	filter, err := sanitizer.FindLogs(ctx, c)
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
	filter.CompanyIDs = []string{currentUser.CompanyID}
	if rows, pagination, err = q.logUseCase.FindLogs(ctx, filter); err != nil {
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
