package presenter

import (
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	productModel "github.com/roysitumorang/sadia/modules/product/model"
	productUseCase "github.com/roysitumorang/sadia/modules/product/usecase"
	sequenceUseCase "github.com/roysitumorang/sadia/modules/sequence/usecase"
	sessionModel "github.com/roysitumorang/sadia/modules/session/model"
	sessionUseCase "github.com/roysitumorang/sadia/modules/session/usecase"
	transactionModel "github.com/roysitumorang/sadia/modules/transaction/model"
	"github.com/roysitumorang/sadia/modules/transaction/sanitizer"
	transactionUseCase "github.com/roysitumorang/sadia/modules/transaction/usecase"
	"go.uber.org/zap"
)

type (
	transactionHTTPHandler struct {
		jwtUseCase         jwtUseCase.JwtUseCase
		accountUseCase     accountUseCase.AccountUseCase
		sessionUseCase     sessionUseCase.SessionUseCase
		productUseCase     productUseCase.ProductUseCase
		sequenceUseCase    sequenceUseCase.SequenceUseCase
		transactionUseCase transactionUseCase.TransactionUseCase
	}
)

func New(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	sessionUseCase sessionUseCase.SessionUseCase,
	productUseCase productUseCase.ProductUseCase,
	sequenceUseCase sequenceUseCase.SequenceUseCase,
	transactionUseCase transactionUseCase.TransactionUseCase,
) *transactionHTTPHandler {
	return &transactionHTTPHandler{
		jwtUseCase:         jwtUseCase,
		accountUseCase:     accountUseCase,
		sessionUseCase:     sessionUseCase,
		productUseCase:     productUseCase,
		sequenceUseCase:    sequenceUseCase,
		transactionUseCase: transactionUseCase,
	}
}

func (q *transactionHTTPHandler) Mount(r fiber.Router) {
	userKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase)
	r.Get("", userKeyAuth, q.UserFindTransactions).
		Post("", userKeyAuth, q.UserCreateTransaction).
		Get("/:id", userKeyAuth, q.UserFindCurrentTransaction)
}

func (q *transactionHTTPHandler) UserFindTransactions(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "TransactionPresenter-UserFindTransactions"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	if currentUser.CurrentSessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active session").WriteResponse(c)
	}
	filter, err := sanitizer.FindTransactions(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindTransactions")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	filter.SessionIDs = []string{*currentUser.CurrentSessionID}
	rows, pagination, err := q.transactionUseCase.FindTransactions(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindTransactions")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *transactionHTTPHandler) UserCreateTransaction(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "TransactionPresenter-UserCreateTransaction"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	if currentUser.CurrentSessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active transaction").WriteResponse(c)
	}
	sessions, _, err := q.sessionUseCase.FindSessions(
		ctx,
		sessionModel.NewFilter(
			sessionModel.WithSessionIDs(*currentUser.CurrentSessionID),
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
	request, statusCode, err := sanitizer.ValidateTransaction(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateTransaction")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	productIDs := make([]string, len(request.LineItems))
	for i, lineItem := range request.LineItems {
		productIDs[i] = lineItem.ProductID
	}
	products, _, err := q.productUseCase.FindProducts(
		ctx,
		productModel.NewFilter(
			productModel.WithCompanyIDs(currentUser.CompanyID),
			productModel.WithProductIDs(productIDs...),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindStores")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(products) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("products not found").WriteResponse(c)
	}
	mapProducts := map[string]*productModel.Product{}
	for _, product := range products {
		mapProducts[product.ID] = product
	}
	if err = request.Calculate(mapProducts); err != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	session.TransactionValue += request.Total
	now := time.Now()
	timeZone := helper.LoadTimeZone()
	period := now.In(timeZone).Format("20060102")
	sequence, err := q.sequenceUseCase.SaveSequence(ctx, fmt.Sprintf("%s-%s", transactionModel.TableName, period), currentUser.ID)
	if err != nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	request.ReferenceNo = fmt.Sprintf(transactionModel.ReferenceNoFormat, period, sequence.Number)
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
	response, err := q.transactionUseCase.CreateTransaction(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateTransaction")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = q.sessionUseCase.UpdateSession(ctx, tx, session); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateSession")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *transactionHTTPHandler) UserFindCurrentTransaction(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "TransactionPresenter-UserFindCurrentTransaction"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	if currentUser.CurrentSessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active transaction").WriteResponse(c)
	}
	transactions, _, err := q.transactionUseCase.FindTransactions(
		ctx,
		transactionModel.NewFilter(
			transactionModel.WithSessionIDs(*currentUser.CurrentSessionID),
			transactionModel.WithTransactionIDs(c.Params("id")),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindTransactions")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(transactions) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("transaction not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(transactions[0]).WriteResponse(c)
}
