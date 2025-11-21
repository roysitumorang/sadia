package presenter

import (
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/utils/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
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
	v1 := r.Group("/v1")
	v1.Group("/admin", middleware.AdminKeyAuth(q.jwtUseCase, q.accountUseCase)).
		Get("", q.AdminFindJWTs).
		Delete("/:id", q.AdminDeleteJWT)
}

func (q *jwtHTTPHandler) AdminFindJWTs(c fiber.Ctx) error {
	ctx := c.Context()
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

func (q *jwtHTTPHandler) AdminDeleteJWT(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "JwtPresenter-AdminDeleteJWT"
	jwtID, err := utils.ParseInt(c.Params("id"))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseInt")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	currentJwt, _ := c.Locals(models.CurrentJwt).(*jwt.RegisteredClaims)
	jsonWebTokens, _, err := q.jwtUseCase.FindJWTs(
		ctx,
		jwtModel.NewFilter(jwtModel.WithJwtIDs(jwtID)),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindJWTs")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(jsonWebTokens) > 0 && jsonWebTokens[0].Token == currentJwt.Subject {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("self delete prohibited").WriteResponse(c)
	}
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
	if _, err = q.jwtUseCase.DeleteJWTs(ctx, tx, jwtModel.NewDeleteFilter(jwtModel.WithDeleteJwtIDs(jwtID))); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}
