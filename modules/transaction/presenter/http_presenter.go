package presenter

import (
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	companyModel "github.com/roysitumorang/sadia/modules/company/model"
	companyUseCase "github.com/roysitumorang/sadia/modules/company/usecase"
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
		sessionStore       *session.Store
		jwtUseCase         jwtUseCase.JwtUseCase
		accountUseCase     accountUseCase.AccountUseCase
		companyUseCase     companyUseCase.CompanyUseCase
		sessionUseCase     sessionUseCase.SessionUseCase
		productUseCase     productUseCase.ProductUseCase
		sequenceUseCase    sequenceUseCase.SequenceUseCase
		transactionUseCase transactionUseCase.TransactionUseCase
	}
)

func New(
	sessionStore *session.Store,
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	companyUseCase companyUseCase.CompanyUseCase,
	sessionUseCase sessionUseCase.SessionUseCase,
	productUseCase productUseCase.ProductUseCase,
	sequenceUseCase sequenceUseCase.SequenceUseCase,
	transactionUseCase transactionUseCase.TransactionUseCase,
) *transactionHTTPHandler {
	return &transactionHTTPHandler{
		sessionStore:       sessionStore,
		jwtUseCase:         jwtUseCase,
		accountUseCase:     accountUseCase,
		companyUseCase:     companyUseCase,
		sessionUseCase:     sessionUseCase,
		productUseCase:     productUseCase,
		sequenceUseCase:    sequenceUseCase,
		transactionUseCase: transactionUseCase,
	}
}

func (q *transactionHTTPHandler) Mount(r fiber.Router) {
	userKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase, q.companyUseCase, q.sessionUseCase)
	v1 := r.Group("/v1")
	v1.Get("", userKeyAuth, q.UserFindTransactions).
		Post("", userKeyAuth, q.UserCreateTransaction).
		Get("/:id", userKeyAuth, q.UserFindTransaction)
}

func (q *transactionHTTPHandler) UserFindTransactions(c *fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "TransactionPresenter-UserFindTransactions"
	currentCompany := c.Locals(models.CurrentCompany).(*companyModel.Company)
	if currentCompany.SessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active session").WriteResponse(c)
	}
	filter, err := sanitizer.FindTransactions(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindTransactions")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	filter.SessionIDs = []string{*currentCompany.SessionID}
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
	ctx := c.Context()
	ctxt := "TransactionPresenter-UserCreateTransaction"
	currentUser := c.Locals(models.CurrentUser).(*accountModel.User)
	currentCompany := c.Locals(models.CurrentCompany).(*companyModel.Company)
	if currentCompany.SessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active session").WriteResponse(c)
	}
	sessions, _, err := q.sessionUseCase.FindSessions(
		ctx,
		sessionModel.NewFilter(
			sessionModel.WithSessionIDs(*currentCompany.SessionID),
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
			productModel.WithCompanyIDs(currentCompany.ID),
			productModel.WithProductIDs(productIDs...),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
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
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCalculate")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	session.TransactionValue += request.Total
	now := time.Now()
	timeZone := helper.LoadTimeZone()
	period := now.In(timeZone).Format("20060102")
	sequence, err := q.sequenceUseCase.SaveSequence(ctx, fmt.Sprintf("%s-%s", transactionModel.TableName, period), currentUser.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSaveSequence")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	request.SessionID = session.ID
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

func (q *transactionHTTPHandler) UserFindTransaction(c *fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "TransactionPresenter-UserFindTransaction"
	currentCompany := c.Locals(models.CurrentCompany).(*companyModel.Company)
	if currentCompany.SessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active session").WriteResponse(c)
	}
	transactions, _, err := q.transactionUseCase.FindTransactions(
		ctx,
		transactionModel.NewFilter(
			transactionModel.WithSessionIDs(*currentCompany.SessionID),
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
