package presenter

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	storeModel "github.com/roysitumorang/sadia/modules/store/model"
	"github.com/roysitumorang/sadia/modules/store/sanitizer"
	storeUseCase "github.com/roysitumorang/sadia/modules/store/usecase"
	"go.uber.org/zap"
)

type (
	storeHTTPHandler struct {
		jwtUseCase     jwtUseCase.JwtUseCase
		accountUseCase accountUseCase.AccountUseCase
		storeUseCase   storeUseCase.StoreUseCase
	}
)

func New(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	storeUseCase storeUseCase.StoreUseCase,
) *storeHTTPHandler {
	return &storeHTTPHandler{
		jwtUseCase:     jwtUseCase,
		accountUseCase: accountUseCase,
		storeUseCase:   storeUseCase,
	}
}

func (q *storeHTTPHandler) Mount(r fiber.Router) {
	userKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase)
	ownerKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase, accountModel.UserLevelOwner)
	r.Get("", userKeyAuth, q.UserFindStores).
		Post("", ownerKeyAuth, q.UserCreateStore).
		Get("/:id", userKeyAuth, q.UserFindStoreByID).
		Put("/:id", ownerKeyAuth, q.UserUpdateStore)
}

func (q *storeHTTPHandler) UserFindStores(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "StorePresenter-UserFindStores"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	filter, err := sanitizer.FindStores(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindStores")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	filter.CompanyIDs = []string{currentUser.CompanyID}
	rows, pagination, err := q.storeUseCase.FindStores(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindStores")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *storeHTTPHandler) UserCreateStore(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "StorePresenter-UserCreateStore"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	request, statusCode, err := sanitizer.ValidateStore(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateStore")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	request.CompanyID = currentUser.CompanyID
	request.CreatedBy = currentUser.ID
	response, err := q.storeUseCase.CreateStore(ctx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateStore")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *storeHTTPHandler) UserFindStoreByID(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "StorePresenter-UserFindStoreByID"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	stores, _, err := q.storeUseCase.FindStores(
		ctx,
		storeModel.NewFilter(
			storeModel.WithStoreIDs(c.Params("id")),
			storeModel.WithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindStores")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(stores) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("store not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(stores[0]).WriteResponse(c)
}

func (q *storeHTTPHandler) UserUpdateStore(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "StorePresenter-UserUpdateStore"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	request, statusCode, err := sanitizer.ValidateStore(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateStore")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	stores, _, err := q.storeUseCase.FindStores(
		ctx,
		storeModel.NewFilter(
			storeModel.WithStoreIDs(c.Params("id")),
			storeModel.WithCompanyIDs(currentUser.CompanyID),
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
	store.Name = request.Name
	store.Slug = request.Slug
	store.UpdatedBy = currentUser.ID
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
	if err = q.storeUseCase.UpdateStore(ctx, tx, store); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateStore")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(store).WriteResponse(c)
}
