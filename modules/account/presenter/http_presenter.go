package presenter

import (
	"errors"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
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
		Get("", q.FindAccounts).
		Post("", q.CreateAccount).
		Get("/:id", q.FindAccount).
		Delete("/:id", q.DeactivateAccount)
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

func (q *accountHTTPHandler) CreateAccount(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-CreateAccount"
	currentAccount, _ := c.Locals(models.CurrentAccount).(*accountModel.Account)
	request, statusCode, err := sanitizer.ValidateAccount(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateAccount")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	request.CreatedBy = &currentAccount.UID
	response, err := q.accountUseCase.CreateAccount(ctx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateAccount")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *accountHTTPHandler) FindAccount(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-FindAccount"
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithLogin(c.Params("id"))),
		url.Values{},
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("account not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(accounts[0]).WriteResponse(c)
}

func (q *accountHTTPHandler) DeactivateAccount(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AccountPresenter-DeactivateAccount"
	currentAccount, _ := c.Locals(models.CurrentAccount).(*accountModel.Account)
	request, statusCode, err := sanitizer.ValidateDeactivation(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateDeactivation")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithLogin(c.Params("id"))),
		url.Values{},
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("account not found").WriteResponse(c)
	}
	account := accounts[0]
	if account.Status != accountModel.StatusActive {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("cannot deactivate unconfirmed & deactivated account").WriteResponse(c)
	}
	now := time.Now()
	account.Status = accountModel.StatusDeactivated
	account.DeactivatedBy = &currentAccount.UID
	account.DeactivatedAt = &now
	account.DeactivationReason = &request.Reason
	tx, err := q.accountUseCase.BeginTx(ctx)
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
	if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if _, err = q.jwtUseCase.DeleteJWTs(ctx, tx, time.Time{}, account.UID); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(account).WriteResponse(c)
}
