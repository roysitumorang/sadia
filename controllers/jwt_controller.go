package controllers

import (
	"errors"
	"strconv"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/repositories"
	"github.com/roysitumorang/sadia/sanitizers"
	"github.com/roysitumorang/sadia/services"
	"go.uber.org/zap"
)

type jwtController struct {
	jwtService     services.JwtService
	accountService services.AccountService
}

func NewJwtController(
	jwtService services.JwtService,
	accountService services.AccountService,
) *jwtController {
	return &jwtController{
		jwtService:     jwtService,
		accountService: accountService,
	}
}

func (q *jwtController) Mount(r fiber.Router) {
	v1 := r.Group("/v1")
	v1.Group("/admin", middleware.AdminKeyAuth(q.jwtService, q.accountService)).
		Get("", q.AdminFindJWTs).
		Delete("/:id", q.AdminDeleteJWT)
}

func (q *jwtController) AdminFindJWTs(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "JwtController-AdminFindJWTs"
	filter, err := sanitizers.FindJWTs(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindJWTs")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	rows, pagination, err := q.jwtService.FindJWTs(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindJWTs")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *jwtController) AdminDeleteJWT(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "JwtController-AdminDeleteJWT"
	currentJwt, _ := c.Locals(models.CurrentJwt).(*jwt.RegisteredClaims)
	jwtID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("JWT not found").WriteResponse(c)
	}
	jsonWebTokens, _, err := q.jwtService.FindJWTs(
		ctx,
		models.NewJwtFilter(models.JwtWithJwtIDs(jwtID)),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindJWTs")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(jsonWebTokens) > 0 && jsonWebTokens[0].Token == currentJwt.Subject {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("self delete prohibited").WriteResponse(c)
	}
	tx, err := repositories.BeginTx(ctx)
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
	if _, err = q.jwtService.DeleteJWTs(ctx, tx, models.NewJwtDeleteFilter(models.JwtWithDeleteJwtIDs(jwtID))); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusNoContent).WriteResponse(c)
}
