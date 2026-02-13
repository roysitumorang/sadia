package presenter

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	companyUseCase "github.com/roysitumorang/sadia/modules/company/usecase"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	logModel "github.com/roysitumorang/sadia/modules/log/model"
	logUseCase "github.com/roysitumorang/sadia/modules/log/usecase"
	productCategoryModel "github.com/roysitumorang/sadia/modules/product_category/model"
	"github.com/roysitumorang/sadia/modules/product_category/sanitizer"
	productCategoryUseCase "github.com/roysitumorang/sadia/modules/product_category/usecase"
	sessionUseCase "github.com/roysitumorang/sadia/modules/session/usecase"
	transactionModel "github.com/roysitumorang/sadia/modules/transaction/model"
	"go.uber.org/zap"
)

type (
	productCategoryHTTPHandler struct {
		jwtUseCase             jwtUseCase.JwtUseCase
		accountUseCase         accountUseCase.AccountUseCase
		companyUseCase         companyUseCase.CompanyUseCase
		sessionUseCase         sessionUseCase.SessionUseCase
		productCategoryUseCase productCategoryUseCase.ProductCategoryUseCase
		logUseCase             logUseCase.LogUseCase
	}
)

func New(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	companyUseCase companyUseCase.CompanyUseCase,
	sessionUseCase sessionUseCase.SessionUseCase,
	productCategoryUseCase productCategoryUseCase.ProductCategoryUseCase,
	logUseCase logUseCase.LogUseCase,
) *productCategoryHTTPHandler {
	return &productCategoryHTTPHandler{
		jwtUseCase:             jwtUseCase,
		accountUseCase:         accountUseCase,
		companyUseCase:         companyUseCase,
		sessionUseCase:         sessionUseCase,
		productCategoryUseCase: productCategoryUseCase,
		logUseCase:             logUseCase,
	}
}

func (q *productCategoryHTTPHandler) Mount(r fiber.Router) {
	userKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase, q.companyUseCase, q.sessionUseCase)
	ownerKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase, q.companyUseCase, q.sessionUseCase, accountModel.UserLevelOwner)
	v1 := r.Group("/v1")
	v1.Get("", userKeyAuth, q.UserFindProductCategories).
		Post("", ownerKeyAuth, q.UserCreateProductCategory).
		Get("/:id", userKeyAuth, q.UserFindProductCategoryByID).
		Put("/:id", ownerKeyAuth, q.UserUpdateProductCategory)
	userSessionAuth := middleware.UserSessionAuth(q.accountUseCase, q.companyUseCase, q.sessionUseCase)
	r.Get("", userSessionAuth, q.userIndex).
		Get("/new", userSessionAuth, q.userNew).
		Post("", userSessionAuth, q.userCreate).
		Get("/:id/edit", userSessionAuth, q.userEdit).
		Post("/:id", userSessionAuth, q.userUpdate)
}

func (q *productCategoryHTTPHandler) UserFindProductCategories(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductCategoryPresenter-UserFindProductCategories"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	filter, err := sanitizer.FindProductCategories(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProductCategories")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	filter.CompanyIDs = []string{currentUser.CompanyID}
	rows, pagination, err := q.productCategoryUseCase.FindProductCategories(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProductCategories")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *productCategoryHTTPHandler) UserCreateProductCategory(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductCategoryPresenter-UserCreateProductCategory"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	request, statusCode, err := sanitizer.ValidateProductCategory(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateProductCategory")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	request.CompanyID = currentUser.CompanyID
	request.CreatedBy = currentUser.ID
	request.CreatedAt = time.Now()
	tx, err := helper.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response, err := q.productCategoryUseCase.CreateProductCategory(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateProductCategory")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	log := &logModel.Log{
		CompanyID: currentUser.CompanyID,
		TableName: productCategoryModel.TableName,
		TableID:   response.ID,
		Action:    logModel.ActionCreate,
		Changes: map[string]logModel.Change{
			"name": {New: response.Name},
			"slug": {New: response.Slug},
		},
		CreatedBy: response.CreatedBy,
		CreatedAt: response.CreatedAt,
	}
	if _, err = q.logUseCase.CreateLog(ctx, tx, log); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateLog")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *productCategoryHTTPHandler) UserFindProductCategoryByID(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductCategoryPresenter-UserFindProductCategoryByID"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	productCategories, _, err := q.productCategoryUseCase.FindProductCategories(
		ctx,
		productCategoryModel.NewFilter(
			productCategoryModel.WithProductCategoryIDs(c.Params("id")),
			productCategoryModel.WithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProductCategories")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(productCategories) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("category not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(productCategories[0]).WriteResponse(c)
}

func (q *productCategoryHTTPHandler) UserUpdateProductCategory(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductCategoryPresenter-UserUpdateProductCategory"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	request, statusCode, err := sanitizer.ValidateProductCategory(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateProductCategory")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	productCategories, _, err := q.productCategoryUseCase.FindProductCategories(
		ctx,
		productCategoryModel.NewFilter(
			productCategoryModel.WithProductCategoryIDs(c.Params("id")),
			productCategoryModel.WithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProductCategories")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(productCategories) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("category not found").WriteResponse(c)
	}
	existing := productCategories[0]
	changes := map[string]logModel.Change{}
	nameChanged := existing.Name != request.Name
	if nameChanged {
		changes["name"] = logModel.Change{
			Old: existing.Name,
			New: request.Name,
		}
	}
	slugChanged := existing.Slug != request.Slug
	if slugChanged {
		changes["slug"] = logModel.Change{
			Old: existing.Slug,
			New: request.Slug,
		}
	}
	if !nameChanged && !slugChanged {
		return helper.NewResponse(fiber.StatusOK).SetData(existing).WriteResponse(c)
	}
	request.ID = existing.ID
	request.UpdatedBy = currentUser.ID
	request.UpdatedAt = time.Now()
	tx, err := helper.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	saved, err := q.productCategoryUseCase.UpdateProductCategory(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProductCategory")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	log := &logModel.Log{
		CompanyID: currentUser.CompanyID,
		TableName: productCategoryModel.TableName,
		TableID:   saved.ID,
		Action:    logModel.ActionUpdate,
		Changes:   changes,
		CreatedBy: saved.CreatedBy,
		CreatedAt: saved.UpdatedAt,
	}
	if _, err = q.logUseCase.CreateLog(ctx, tx, log); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateLog")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(saved).WriteResponse(c)
}

func (q *productCategoryHTTPHandler) userIndex(c fiber.Ctx) error {
	ctxt := "ProductCategoryPresenter-userIndex"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	pagination := new(models.Pagination)
	var rows []*productCategoryModel.ProductCategory
	filter, err := sanitizer.FindProductCategories(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProductCategories")
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("product_category/index", fiber.Map{
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
	filter.CompanyIDs = []string{currentUser.CompanyID}
	if rows, pagination, err = q.productCategoryUseCase.FindProductCategories(ctx, filter); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProductCategories")
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("product_category/index", fiber.Map{
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
	return c.Render("product_category/index", fiber.Map{
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

func (q *productCategoryHTTPHandler) userNew(c fiber.Ctx) error {
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	request := new(productCategoryModel.ProductCategory)
	defer flash.Clear(c, sess.Session)
	return c.Render("product_category/new", fiber.Map{
		"authenticated": true,
		"currentUser":   currentUser,
		"flash":         flash,
		"request":       request,
		"cart":          cart,
		"path":          c.Route().Path,
	})
}

func (q *productCategoryHTTPHandler) userCreate(c fiber.Ctx) error {
	ctxt := "ProductCategoryPresenter-userCreate"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	request, statusCode, err := sanitizer.ValidateProductCategory(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateProductCategory")
		c.Response().SetStatusCode(statusCode)
		return c.Render("product_category/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"cart":          cart,
			"path":          c.Route().Path,
		})
	}
	request.CompanyID = currentUser.CompanyID
	request.CreatedBy = currentUser.ID
	request.CreatedAt = time.Now()
	tx, err := helper.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("product_category/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"cart":          cart,
			"path":          c.Route().Path,
		})
	}
	productCategory, err := q.productCategoryUseCase.CreateProductCategory(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateProductCategory")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("product_category/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"cart":          cart,
			"path":          c.Route().Path,
		})
	}
	log := &logModel.Log{
		CompanyID: currentUser.CompanyID,
		TableName: productCategoryModel.TableName,
		TableID:   productCategory.ID,
		Action:    logModel.ActionCreate,
		Changes: map[string]logModel.Change{
			"name": {New: productCategory.Name},
			"slug": {New: productCategory.Slug},
		},
		CreatedBy: currentUser.ID,
		CreatedAt: productCategory.CreatedAt,
	}
	if _, err = q.logUseCase.CreateLog(ctx, tx, log); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateLog")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("product_category/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"cart":          cart,
			"path":          c.Route().Path,
		})
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("product_category/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"cart":          cart,
			"path":          c.Route().Path,
		})
	}
	return flash.Clear(c, sess.Session).Success("category created successfully").Redirect(c, sess.Session, "/product_category")
}

func (q *productCategoryHTTPHandler) userEdit(c fiber.Ctx) error {
	ctxt := "ProductCategoryPresenter-userEdit"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	request := new(productCategoryModel.ProductCategory)
	productCategories, _, err := q.productCategoryUseCase.FindProductCategories(
		ctx,
		productCategoryModel.NewFilter(
			productCategoryModel.WithProductCategoryIDs(c.Params("id")),
			productCategoryModel.WithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProductCategories")
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("product_category/edit", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"cart":          cart,
			"path":          c.Route().Path,
		})
	}
	if len(productCategories) == 0 {
		return flash.Danger("category not found").Redirect(c, sess.Session, "/product_category")
	}
	defer flash.Clear(c, sess.Session)
	return c.Render("product_category/edit", fiber.Map{
		"authenticated": true,
		"currentUser":   currentUser,
		"flash":         flash,
		"request":       productCategories[0],
		"cart":          cart,
		"path":          c.Route().Path,
	})
}

func (q *productCategoryHTTPHandler) userUpdate(c fiber.Ctx) error {
	ctxt := "ProductCategoryPresenter-userUpdate"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	request, statusCode, err := sanitizer.ValidateProductCategory(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateProductCategory")
		c.Response().SetStatusCode(statusCode)
		return c.Render("product_category/edit", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"cart":          cart,
			"path":          c.Route().Path,
		})
	}
	productCategories, _, err := q.productCategoryUseCase.FindProductCategories(
		ctx,
		productCategoryModel.NewFilter(
			productCategoryModel.WithProductCategoryIDs(c.Params("id")),
			productCategoryModel.WithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProductCategories")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("product_category/edit", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
			"cart":          cart,
			"path":          c.Route().Path,
		})
	}
	if len(productCategories) == 0 {
		return flash.Danger("category not found").Redirect(c, sess.Session, "/product_category")
	}
	existing := productCategories[0]
	changes := map[string]logModel.Change{}
	nameChanged := existing.Name != request.Name
	if nameChanged {
		changes["name"] = logModel.Change{
			Old: existing.Name,
			New: request.Name,
		}
	}
	slugChanged := existing.Slug != request.Slug
	if slugChanged {
		changes["slug"] = logModel.Change{
			Old: existing.Slug,
			New: request.Slug,
		}
	}
	if nameChanged || slugChanged {
		request.ID = existing.ID
		request.UpdatedBy = currentUser.ID
		request.UpdatedAt = time.Now()
		tx, err := helper.BeginTx(ctx)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
			c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
			return c.Render("product_category/edit", fiber.Map{
				"authenticated": true,
				"currentUser":   currentUser,
				"flash":         flash.Danger(err.Error()),
				"request":       request,
				"cart":          cart,
				"path":          c.Route().Path,
			})
		}
		saved, err := q.productCategoryUseCase.UpdateProductCategory(ctx, tx, request)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProductCategory")
			c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
			return c.Render("product_category/edit", fiber.Map{
				"authenticated": true,
				"currentUser":   currentUser,
				"flash":         flash.Danger(err.Error()),
				"request":       request,
				"cart":          cart,
				"path":          c.Route().Path,
			})
		}
		log := &logModel.Log{
			CompanyID: currentUser.CompanyID,
			TableName: productCategoryModel.TableName,
			TableID:   saved.ID,
			Action:    logModel.ActionUpdate,
			Changes:   changes,
			CreatedBy: currentUser.ID,
			CreatedAt: saved.UpdatedAt,
		}
		if _, err = q.logUseCase.CreateLog(ctx, tx, log); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateLog")
			c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
			return c.Render("product_category/edit", fiber.Map{
				"authenticated": true,
				"currentUser":   currentUser,
				"flash":         flash.Danger(err.Error()),
				"request":       request,
				"cart":          cart,
				"path":          c.Route().Path,
			})
		}
		if err = tx.Commit(ctx); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
			c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
			return c.Render("product_category/edit", fiber.Map{
				"authenticated": true,
				"currentUser":   currentUser,
				"flash":         flash.Danger(err.Error()),
				"request":       request,
				"cart":          cart,
				"path":          c.Route().Path,
			})
		}
	}
	return flash.Clear(c, sess.Session).Success("category updated successfully").Redirect(c, sess.Session, "/product_category")
}
