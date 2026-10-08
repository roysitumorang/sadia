package controllers

import (
	"errors"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/repositories"
	"github.com/roysitumorang/sadia/sanitizers"
	"github.com/roysitumorang/sadia/services"
	"go.uber.org/zap"
)

type (
	transactionController struct {
		jwtService         services.JwtService
		accountService     services.AccountService
		companyService     services.CompanyService
		sessionService     services.SessionService
		productService     services.ProductService
		sequenceService    services.SequenceService
		transactionService services.TransactionService
	}
)

func NewTransactionController(
	jwtService services.JwtService,
	accountService services.AccountService,
	companyService services.CompanyService,
	sessionService services.SessionService,
	productService services.ProductService,
	sequenceService services.SequenceService,
	transactionService services.TransactionService,
) *transactionController {
	return &transactionController{
		jwtService:         jwtService,
		accountService:     accountService,
		companyService:     companyService,
		sessionService:     sessionService,
		productService:     productService,
		sequenceService:    sequenceService,
		transactionService: transactionService,
	}
}

func (q *transactionController) Mount(r fiber.Router) {
	userKeyAuth := middleware.UserKeyAuth(q.jwtService, q.accountService, q.companyService, q.sessionService)
	v1 := r.Group("/v1")
	v1.Get("", userKeyAuth, q.UserFindTransactions).
		Post("", userKeyAuth, q.UserCreateTransaction).
		Get("/:id", userKeyAuth, q.UserFindTransaction)
	userSessionAuth := middleware.UserSessionAuth(q.accountService, q.companyService, q.sessionService)
	r.Get("", userSessionAuth, q.userIndex).
		Get("/new", userSessionAuth, q.userNew).
		Post("", userSessionAuth, q.userCreate).
		Get("/:id", userSessionAuth, q.userShow).
		Post("/cart/line-item", userSessionAuth, q.userCreateCartLineItem).
		Get("/cart/line-item/:id/delete", userSessionAuth, q.userRemoveCartLineItem)
}

func (q *transactionController) UserFindTransactions(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "TransactionPresenter-UserFindTransactions"
	currentCompany := c.Locals(models.CurrentCompany).(*models.Company)
	if currentCompany.SessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active session").WriteResponse(c)
	}
	filter, err := sanitizers.FindTransactions(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindTransactions")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	filter.SessionIDs = []uint64{*currentCompany.SessionID}
	rows, pagination, err := q.transactionService.FindTransactions(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindTransactions")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *transactionController) UserCreateTransaction(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "TransactionPresenter-UserCreateTransaction"
	currentUser := c.Locals(models.CurrentUser).(*models.User)
	currentCompany := c.Locals(models.CurrentCompany).(*models.Company)
	if currentCompany.SessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active session").WriteResponse(c)
	}
	sessions, _, err := q.sessionService.FindSessions(
		ctx,
		models.NewSessionFilter(
			models.SessionWithSessionIDs(*currentCompany.SessionID),
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
	request, statusCode, err := sanitizers.ValidateTransaction(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateTransaction")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	productIDs := make([]uint64, len(request.LineItems))
	for i, lineItem := range request.LineItems {
		productIDs[i] = lineItem.ProductID
	}
	products, _, err := q.productService.FindProducts(
		ctx,
		models.NewProductFilter(
			models.ProductWithCompanyIDs(currentCompany.ID),
			models.ProductWithProductIDs(productIDs...),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(products) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("products not found").WriteResponse(c)
	}
	mapProducts := map[uint64]*models.Product{}
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
	sequence, err := q.sequenceService.SaveSequence(ctx, helper.Sprintf("%s-%s", models.TransactionTableName, period), currentUser.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSaveSequence")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	request.SessionID = session.ID
	request.ReferenceNo = helper.Sprintf(models.ReferenceNoFormat, period, sequence.Number)
	request.CreatedBy = currentUser.ID
	tx, err := repositories.BeginTx(ctx)
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
	response, err := q.transactionService.CreateTransaction(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateTransaction")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = q.sessionService.UpdateSession(ctx, tx, session); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateSession")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *transactionController) UserFindTransaction(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "TransactionPresenter-UserFindTransaction"
	currentCompany := c.Locals(models.CurrentCompany).(*models.Company)
	if currentCompany.SessionID == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("you don't have any active session").WriteResponse(c)
	}
	transactionID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("transaction not found").WriteResponse(c)
	}
	transactions, _, err := q.transactionService.FindTransactions(
		ctx,
		models.NewTransactionFilter(
			models.TransactionWithSessionIDs(*currentCompany.SessionID),
			models.TransactionWithTransactionIDs(transactionID),
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

func (q *transactionController) userIndex(c fiber.Ctx) error {
	ctxt := "TransactionPresenter-userIndex"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	pagination := new(models.Pagination)
	var rows []*models.Transaction
	filter, err := sanitizers.FindTransactions(ctx, c)
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
			"path":          c.Route().Path,
		})
	}
	filter.CompanyIDs = []uint64{currentUser.CompanyID}
	if rows, pagination, err = q.transactionService.FindTransactions(ctx, filter); err != nil {
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
			"path":          c.Route().Path,
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
		"path":          c.Route().Path,
	})
}

func (q *transactionController) userNew(c fiber.Ctx) error {
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	currentCompany := sess.Get(models.CurrentCompany).(*models.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	if currentCompany.SessionID == nil {
		return c.Redirect().To("/session")
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	flash.Clear(c, sess.Session)
	return c.Render("transaction/new", fiber.Map{
		"authenticated": true,
		"currentUser":   currentUser,
		"flash":         flash,
		"cart":          cart,
		"request":       cart,
		"path":          c.Route().Path,
	})
}

func (q *transactionController) userCreate(c fiber.Ctx) error {
	ctxt := "TransactionPresenter-userCreate"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	currentCompany := sess.Get(models.CurrentCompany).(*models.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	if currentCompany.SessionID == nil {
		return c.Redirect().To("/session")
	}
	currentSession := sess.Get(models.CurrentSession).(*models.Session)
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	request, statusCode, err := sanitizers.ValidateCart(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateCart")
		c.Response().SetStatusCode(statusCode)
		return c.Render("transaction/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash,
			"cart":          cart,
			"request":       request,
			"path":          c.Route().Path,
		})
	}
	productIDs := make([]uint64, len(request.LineItems))
	for i, lineItem := range request.LineItems {
		productIDs[i] = lineItem.ProductID
	}
	products, _, err := q.productService.FindProducts(
		ctx,
		models.NewProductFilter(
			models.ProductWithCompanyIDs(currentCompany.ID),
			models.ProductWithProductIDs(productIDs...),
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
			"path":          c.Route().Path,
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
			"path":          c.Route().Path,
		})
	}
	mapProducts := map[uint64]*models.Product{}
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
			"path":          c.Route().Path,
		})
	}
	now := time.Now()
	timeZone := helper.LoadTimeZone()
	period := now.In(timeZone).Format("20060102")
	sequence, err := q.sequenceService.SaveSequence(ctx, helper.Sprintf("%s-%s", models.TransactionTableName, period), currentUser.ID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSaveSequence")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("transaction/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"cart":          cart,
			"request":       request,
			"path":          c.Route().Path,
		})
	}
	request.SessionID = currentSession.ID
	request.ReferenceNo = helper.Sprintf(models.ReferenceNoFormat, period, sequence.Number)
	request.CreatedBy = currentUser.ID
	tx, err := repositories.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("transaction/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"cart":          cart,
			"request":       request,
			"path":          c.Route().Path,
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
	if _, err = q.transactionService.CreateTransaction(ctx, tx, request); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateTransaction")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("transaction/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"cart":          cart,
			"request":       request,
			"path":          c.Route().Path,
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
			"path":          c.Route().Path,
		})
	}
	cart = &models.Transaction{
		LineItems: []*models.LineItem{},
	}
	sess.Set(models.CurrentCart, cart)
	return flash.Success("transaction created successfully").Redirect(c, sess.Session, "/transaction")
}

func (q *transactionController) userShow(c fiber.Ctx) error {
	ctxt := "TransactionPresenter-userShow"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	currentCompany := sess.Get(models.CurrentCompany).(*models.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	transactionID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return flash.Danger("transaction not found").Redirect(c, sess.Session, "/transaction")
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	transactions, _, err := q.transactionService.FindTransactions(
		ctx,
		models.NewTransactionFilter(
			models.TransactionWithCompanyIDs(currentCompany.ID),
			models.TransactionWithTransactionIDs(transactionID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindTransactions")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(transactions) == 0 {
		return flash.Danger("transaction not found").Redirect(c, sess.Session, "/transaction")
	}
	transaction := transactions[0]
	defer flash.Clear(c, sess.Session)
	return c.Render("transaction/show", fiber.Map{
		"authenticated":  true,
		"currentUser":    currentUser,
		"flash":          flash,
		"currentCompany": currentCompany,
		"transaction":    transaction,
		"cart":           cart,
		"path":           c.Route().Path,
	})
}

func (q *transactionController) userCreateCartLineItem(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "TransactionPresenter-userCreateCartLineItem"
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	currentCompany := sess.Get(models.CurrentCompany).(*models.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	if currentCompany.SessionID == nil {
		return c.Redirect().To("/session")
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	request, statusCode, err := sanitizers.ValidateLineItem(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateLineItem")
		return flash.Danger(err.Error()).Redirect(c, sess.Session, "/product", statusCode)
	}
	var productIDs []uint64
	for _, lineItem := range cart.LineItems {
		productIDs = append(productIDs, lineItem.ProductID)
	}
	productIDs = append(productIDs, request.ProductID)
	products, _, err := q.productService.FindProducts(
		ctx,
		models.NewProductFilter(
			models.ProductWithProductIDs(productIDs...),
			models.ProductWithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
	}
	if len(products) == 0 {
		return flash.Danger("product not found").Redirect(c, sess.Session, "/product")
	}
	mapProducts := map[uint64]*models.Product{}
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
	sess.Set(models.CurrentCart, cart)
	return flash.Success("product added to cart successfully").Redirect(c, sess.Session, "/product")
}

func (q *transactionController) userRemoveCartLineItem(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "TransactionPresenter-userRemoveCartLineItem"
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	currentCompany := sess.Get(models.CurrentCompany).(*models.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	if currentCompany.SessionID == nil {
		return c.Redirect().To("/session")
	}
	cartLineItemID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return flash.Danger("product not found").Redirect(c, sess.Session, "/product")
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	var (
		lineItems  []*models.LineItem
		productIDs []uint64
	)
	for _, lineItem := range cart.LineItems {
		if lineItem.ProductID != cartLineItemID {
			lineItems = append(lineItems, lineItem)
			productIDs = append(productIDs, lineItem.ProductID)
		}
	}
	products, _, err := q.productService.FindProducts(
		ctx,
		models.NewProductFilter(
			models.ProductWithProductIDs(productIDs...),
			models.ProductWithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
	}
	if len(products) == 0 {
		return flash.Danger("product not found").Redirect(c, sess.Session, "/product")
	}
	mapProducts := map[uint64]*models.Product{}
	for _, product := range products {
		mapProducts[product.ID] = product
	}
	cart.LineItems = lineItems
	if err = cart.Calculate(mapProducts); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCalculate")
		return flash.Danger(err.Error()).Redirect(c, sess.Session, "/product")
	}
	sess.Set(models.CurrentCart, cart)
	return flash.Success("line item deleted successfully").Redirect(c, sess.Session, "/transaction/new")
}
