package presenter

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	jwtModel "github.com/roysitumorang/sadia/modules/jwt/model"
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
	r.Group("/admin", middleware.AdminKeyAuth(q.jwtUseCase, q.accountUseCase)).
		Get("", q.AdminFindJWTs).
		Delete("/:id", q.AdminDeleteJWT)
}

func (q *jwtHTTPHandler) AdminFindJWTs(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "JwtPresenter-AdminFindJWTs"
	filter, err := sanitizer.FindJWTs(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindJWTs")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	rows, pagination, err := q.jwtUseCase.FindJWTs(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindJWTs")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *jwtHTTPHandler) AdminDeleteJWT(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "JwtPresenter-AdminDeleteJWT"
	tx, err := helper.BeginTx(ctx)
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
	if _, err = q.jwtUseCase.DeleteJWTs(ctx, tx, jwtModel.NewDeleteFilter(jwtModel.WithJwtIDs(c.Params("id")))); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}
