package presenter

import (
	"github.com/gofiber/fiber/v2"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	"github.com/roysitumorang/sadia/modules/account/sanitizer"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
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
	r.Group("/admin", middleware.KeyAuth(q.jwtUseCase, q.accountUseCase, accountModel.AccountTypeAdmin)).
		Get("", q.FindAccounts)
}

func (q *accountHTTPHandler) FindAccounts(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-FindAccounts"
	filter, urlValues, err := sanitizer.FindAccounts(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	rows, pagination, err := q.accountUseCase.FindAccounts(
		ctx,
		filter,
		urlValues,
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]interface{}{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}
