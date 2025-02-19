package presenter

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
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
	r.Use(middleware.KeyAuth(q.jwtUseCase, q.accountUseCase)).
		Get("", q.FindJWTs).
		Delete("/:id", q.DeleteJWT)
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
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindJWTs")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]interface{}{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *jwtHTTPHandler) DeleteJWT(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AuthPresenter-DeleteJWT"
	tx, err := q.accountUseCase.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
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
	if _, err = q.jwtUseCase.DeleteJWTs(ctx, tx, time.Time{}, 0, c.Params("id")); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}
