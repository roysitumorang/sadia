package presenter

import (
	"github.com/gofiber/fiber/v2"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	"github.com/roysitumorang/sadia/modules/jwt/sanitizer"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	"go.uber.org/zap"
)

type (
	jwtHTTPHandler struct {
		jwtUseCase     jwtUseCase.JwtUseCase
		accountUseCase accountUseCase.AccountUseCase
	}
)

func New(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
) *jwtHTTPHandler {
	return &jwtHTTPHandler{
		jwtUseCase:     jwtUseCase,
		accountUseCase: accountUseCase,
	}
}

func (q *jwtHTTPHandler) Mount(r fiber.Router) {
	r.Get("", middleware.KeyAuth(q.jwtUseCase, q.accountUseCase), q.FindJWTs)
}

func (q *jwtHTTPHandler) FindJWTs(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AuthPresenter-FindJWTs"
	filter, urlValues := sanitizer.FindJWTS(ctx, c)
	rows, pagination, err := q.jwtUseCase.FindJWTs(
		ctx,
		filter,
		urlValues,
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrLogin")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]interface{}{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}
