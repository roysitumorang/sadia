package presenter

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
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
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	companyUseCase companyUseCase.CompanyUseCase,
	sessionUseCase sessionUseCase.SessionUseCase,
	productUseCase productUseCase.ProductUseCase,
	sequenceUseCase sequenceUseCase.SequenceUseCase,
	transactionUseCase transactionUseCase.TransactionUseCase,
) *transactionHTTPHandler {
	return &transactionHTTPHandler{
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
	userSessionAuth := middleware.UserSessionAuth(q.accountUseCase, q.companyUseCase, q.sessionUseCase)
	r.Get("", userSessionAuth, q.userIndex).
		Get("/new", userSessionAuth, q.userNew).
		Post("", userSessionAuth, q.userCreate).
		Post("/cart/line-item", userSessionAuth, q.userCreateCartLineItem).
		Get("/cart/line-item/:id/delete", userSessionAuth, q.userRemoveCartLineItem)
}

func (q *transactionHTTPHandler) UserFindTransactions(c fiber.Ctx) error {
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
	filter.SessionIDs = []int64{*currentCompany.SessionID}
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

func (q *transactionHTTPHandler) UserCreateTransaction(c fiber.Ctx) error {
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
	productIDs := make([]int64, len(request.LineItems))
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
	mapProducts := map[int64]*productModel.Product{}
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

func (q *transactionHTTPHandler) UserFindTransaction(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "TransactionPresenter-UserFindTransaction"
	transactionID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseInt")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	currentCompany := c.Locals(models.CurrentCompany).(*companyModel.Company)
	if currentCompany.SessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active session").WriteResponse(c)
	}
	transactions, _, err := q.transactionUseCase.FindTransactions(
		ctx,
		transactionModel.NewFilter(
			transactionModel.WithSessionIDs(*currentCompany.SessionID),
			transactionModel.WithTransactionIDs(transactionID),
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

func (q *transactionHTTPHandler) userIndex(c fiber.Ctx) error {
	ctxt := "TransactionPresenter-userIndex"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	pagination := new(models.Pagination)
	var rows []*transactionModel.Transaction
	filter, err := sanitizer.FindTransactions(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindTransactions")
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("transaction/index", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"q":             c.Query("q"),
			"rows":          rows,
			"pagination":    pagination,
			"limits":        models.Limits,
			"cart":          cart,
		})
	}
	filter.CompanyIDs = []int64{currentUser.CompanyID}
	if rows, pagination, err = q.transactionUseCase.FindTransactions(ctx, filter); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindTransactions")
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("transaction/index", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"q":             c.Query("q"),
			"rows":          rows,
			"pagination":    pagination,
			"limits":        models.Limits,
			"cart":          cart,
		})
	}
	defer flash.Clear(c, sess.Session)
	return c.Render("transaction/index", fiber.Map{
		"authenticated": true,
		"currentUser":   currentUser,
		"flash":         flash,
		"q":             c.Query("q"),
		"rows":          rows,
		"pagination":    pagination,
		"limits":        models.Limits,
		"cart":          cart,
	})
}

func (q *transactionHTTPHandler) userNew(c fiber.Ctx) error {
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	currentCompany := sess.Get(models.CurrentCompany).(*companyModel.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	if currentCompany.SessionID == nil {
		return c.Redirect().To("/session")
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	flash.Clear(c, sess.Session)
	return c.Render("transaction/new", fiber.Map{
		"authenticated": true,
		"currentUser":   currentUser,
		"flash":         flash,
		"cart":          cart,
		"request":       cart,
	})
}

func (q *transactionHTTPHandler) userCreate(c fiber.Ctx) error {
	ctxt := "TransactionPresenter-userCreate"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	currentCompany := sess.Get(models.CurrentCompany).(*companyModel.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	if currentCompany.SessionID == nil {
		return c.Redirect().To("/session")
	}
	currentSession := sess.Get(models.CurrentSession).(*sessionModel.Session)
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	request, statusCode, err := sanitizer.ValidateCart(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateCart")
		c.Response().SetStatusCode(statusCode)
		return c.Render("transaction/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash,
			"cart":          cart,
			"request":       request,
		})
	}
	productIDs := make([]int64, len(request.LineItems))
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
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("transaction/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"cart":          cart,
			"request":       request,
		})
	}
	if len(products) == 0 {
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("transaction/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger("products not found"),
			"cart":          cart,
			"request":       request,
		})
	}
	mapProducts := map[int64]*productModel.Product{}
	for _, product := range products {
		mapProducts[product.ID] = product
	}
	if err = request.Calculate(mapProducts); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCalculate")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("transaction/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"cart":          cart,
			"request":       request,
		})
	}
	now := time.Now()
	timeZone := helper.LoadTimeZone()
	period := now.In(timeZone).Format("20060102")
	sequence, err := q.sequenceUseCase.SaveSequence(ctx, fmt.Sprintf("%s-%s", transactionModel.TableName, period), currentUser.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSaveSequence")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("transaction/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"cart":          cart,
			"request":       request,
		})
	}
	request.SessionID = currentSession.ID
	request.ReferenceNo = fmt.Sprintf(transactionModel.ReferenceNoFormat, period, sequence.Number)
	request.CreatedBy = currentUser.ID
	tx, err := helper.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("transaction/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"cart":          cart,
			"request":       request,
		})
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
	if _, err = q.transactionUseCase.CreateTransaction(ctx, tx, request); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateTransaction")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("transaction/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"cart":          cart,
			"request":       request,
		})
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("transaction/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"cart":          cart,
			"request":       request,
		})
	}
	cart = &transactionModel.Transaction{
		LineItems: []*transactionModel.LineItem{},
	}
	sess.Set(transactionModel.CurrentCart, cart)
	return flash.Success("transaction created successfully").Redirect(c, sess.Session, "/transaction")
}

func (q *transactionHTTPHandler) userCreateCartLineItem(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "TransactionPresenter-userCreateCartLineItem"
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	currentCompany := sess.Get(models.CurrentCompany).(*companyModel.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	if currentCompany.SessionID == nil {
		return c.Redirect().To("/session")
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	request, statusCode, err := sanitizer.ValidateLineItem(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateLineItem")
		return flash.Danger(err.Error()).Redirect(c, sess.Session, "/product", statusCode)
	}
	var productIDs []int64
	for _, lineItem := range cart.LineItems {
		productIDs = append(productIDs, lineItem.ProductID)
	}
	productIDs = append(productIDs, request.ProductID)
	products, _, err := q.productUseCase.FindProducts(
		ctx,
		productModel.NewFilter(
			productModel.WithProductIDs(productIDs...),
			productModel.WithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
	}
	if len(products) == 0 {
		return flash.Danger("product not found").Redirect(c, sess.Session, "/product")
	}
	mapProducts := map[int64]*productModel.Product{}
	for _, product := range products {
		mapProducts[product.ID] = product
	}
	var exists bool
	for i, item := range cart.LineItems {
		if exists = item.ProductID == request.ProductID; exists {
			cart.LineItems[i] = request
			break
		}
	}
	if !exists {
		cart.LineItems = append(cart.LineItems, request)
	}
	if err = cart.Calculate(mapProducts); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCalculate")
		return flash.Danger(err.Error()).Redirect(c, sess.Session, "/product")
	}
	sess.Set(transactionModel.CurrentCart, cart)
	return flash.Success("product added to cart successfully").Redirect(c, sess.Session, "/product")
}

func (q *transactionHTTPHandler) userRemoveCartLineItem(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "TransactionPresenter-userRemoveCartLineItem"
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	currentCompany := sess.Get(models.CurrentCompany).(*companyModel.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	if currentCompany.SessionID == nil {
		return c.Redirect().To("/session")
	}
	productID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseInt")
		return flash.Danger("line item not found").Redirect(c, sess.Session, "/transaction/new")
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	var (
		lineItems  []*transactionModel.LineItem
		productIDs []int64
	)
	for _, lineItem := range cart.LineItems {
		if lineItem.ProductID != productID {
			lineItems = append(lineItems, lineItem)
			productIDs = append(productIDs, lineItem.ProductID)
		}
	}
	products, _, err := q.productUseCase.FindProducts(
		ctx,
		productModel.NewFilter(
			productModel.WithProductIDs(productIDs...),
			productModel.WithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
	}
	if len(products) == 0 {
		return flash.Danger("product not found").Redirect(c, sess.Session, "/product")
	}
	mapProducts := map[int64]*productModel.Product{}
	for _, product := range products {
		mapProducts[product.ID] = product
	}
	cart.LineItems = lineItems
	if err = cart.Calculate(mapProducts); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCalculate")
		return flash.Danger(err.Error()).Redirect(c, sess.Session, "/product")
	}
	sess.Set(transactionModel.CurrentCart, cart)
	return flash.Success("line item deleted successfully").Redirect(c, sess.Session, "/transaction/new")
}
