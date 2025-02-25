package presenter

import (
	"errors"
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	sessionModel "github.com/roysitumorang/sadia/modules/session/model"
	"github.com/roysitumorang/sadia/modules/session/sanitizer"
	sessionUseCase "github.com/roysitumorang/sadia/modules/session/usecase"
	storeModel "github.com/roysitumorang/sadia/modules/store/model"
	storeUseCase "github.com/roysitumorang/sadia/modules/store/usecase"
	"go.uber.org/zap"
)

type (
	sessionHTTPHandler struct {
		jwtUseCase     jwtUseCase.JwtUseCase
		accountUseCase accountUseCase.AccountUseCase
		storeUseCase   storeUseCase.StoreUseCase
		sessionUseCase sessionUseCase.SessionUseCase
	}
)

func New(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	storeUseCase storeUseCase.StoreUseCase,
	sessionUseCase sessionUseCase.SessionUseCase,
) *sessionHTTPHandler {
	return &sessionHTTPHandler{
		jwtUseCase:     jwtUseCase,
		accountUseCase: accountUseCase,
		storeUseCase:   storeUseCase,
		sessionUseCase: sessionUseCase,
	}
}

func (q *sessionHTTPHandler) Mount(r fiber.Router) {
	userKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase)
	r.Get("", userKeyAuth, q.UserFindSessions).
		Post("", userKeyAuth, q.UserCreateSession).
		Get("/mine", userKeyAuth, q.UserFindCurrentSession).
		Put("/mine", userKeyAuth, q.UserUpdateCurrentSession)
}

func (q *sessionHTTPHandler) UserFindSessions(c *fiber.Ctx) error {
	ctx := c.UserContext()
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
	ctx := c.UserContext()
	ctxt := "SessionPresenter-UserCreateSession"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	if currentUser.CurrentSessionID != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("close user current session before starting new session").WriteResponse(c)
	}
	request, statusCode, err := sanitizer.ValidateNewSession(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateNewSession")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	stores, _, err := q.storeUseCase.FindStores(
		ctx,
		storeModel.NewFilter(
			storeModel.WithCompanyIDs(currentUser.CompanyID),
			storeModel.WithStoreIDs(request.StoreID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindStores")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(stores) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("store not found").WriteResponse(c)
	}
	store := stores[0]
	if store.CurrentSessionID != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("close store current session before starting new session").WriteResponse(c)
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
	store.CurrentSessionID = &response.ID
	if err = q.storeUseCase.UpdateStore(ctx, tx, store); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateStore")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	currentUser.CurrentSessionID = &response.ID
	if err = q.accountUseCase.UpdateUser(ctx, tx, currentUser); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *sessionHTTPHandler) UserFindCurrentSession(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "SessionPresenter-UserFindCurrentSession"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	if currentUser.CurrentSessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active session").WriteResponse(c)
	}
	sessions, _, err := q.sessionUseCase.FindSessions(
		ctx,
		sessionModel.NewFilter(
			sessionModel.WithSessionIDs(*currentUser.CurrentSessionID),
			sessionModel.WithUrlValues(url.Values{}),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindSessions")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(sessions) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("session not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(sessions[0]).WriteResponse(c)
}

func (q *sessionHTTPHandler) UserUpdateCurrentSession(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "SessionPresenter-UserUpdateCurrentSession"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	if currentUser.CurrentSessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active session").WriteResponse(c)
	}
	request, statusCode, err := sanitizer.ValidateCloseSession(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateCloseSession")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	sessions, _, err := q.sessionUseCase.FindSessions(
		ctx,
		sessionModel.NewFilter(
			sessionModel.WithSessionIDs(*currentUser.CurrentSessionID),
			sessionModel.WithUrlValues(url.Values{}),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindSessions")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(sessions) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("session not found").WriteResponse(c)
	}
	session := sessions[0]
	stores, _, err := q.storeUseCase.FindStores(
		ctx,
		storeModel.NewFilter(
			storeModel.WithStoreIDs(session.StoreID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindStores")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(stores) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("store not found").WriteResponse(c)
	}
	store := stores[0]
	session.TakeMoneyValue = request.TakeMoneyValue
	session.TakeMoneyLineItems = make([]*sessionModel.TakeMoneyLineItem, len(request.TakeMoneyLineItems))
	for i, lineItem := range request.TakeMoneyLineItems {
		session.TakeMoneyLineItems[i] = &sessionModel.TakeMoneyLineItem{
			Description: lineItem.Description,
			Value:       lineItem.Value,
		}
	}
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
	if err = q.sessionUseCase.UpdateSession(ctx, tx, session); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateSession")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	store.CurrentSessionID = nil
	if err = q.storeUseCase.UpdateStore(ctx, tx, store); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateStore")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	currentUser.CurrentSessionID = nil
	if err = q.accountUseCase.UpdateUser(ctx, tx, currentUser); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(session).WriteResponse(c)
}
