package presenter

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	productCategoryModel "github.com/roysitumorang/sadia/modules/product_category/model"
	"github.com/roysitumorang/sadia/modules/product_category/sanitizer"
	productCategoryUseCase "github.com/roysitumorang/sadia/modules/product_category/usecase"
	"go.uber.org/zap"
)

type (
	productCategoryHTTPHandler struct {
		sessionStore           *session.Store
		jwtUseCase             jwtUseCase.JwtUseCase
		accountUseCase         accountUseCase.AccountUseCase
		productCategoryUseCase productCategoryUseCase.ProductCategoryUseCase
	}
)

func New(
	sessionStore *session.Store,
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	productCategoryUseCase productCategoryUseCase.ProductCategoryUseCase,
) *productCategoryHTTPHandler {
	return &productCategoryHTTPHandler{
		sessionStore:           sessionStore,
		jwtUseCase:             jwtUseCase,
		accountUseCase:         accountUseCase,
		productCategoryUseCase: productCategoryUseCase,
	}
}

func (q *productCategoryHTTPHandler) Mount(r fiber.Router) {
	userKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase)
	ownerKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase, accountModel.UserLevelOwner)
	v1 := r.Group("/v1")
	v1.Get("", userKeyAuth, q.UserFindProductCategories).
		Post("", ownerKeyAuth, q.UserCreateProductCategory).
		Get("/:id", userKeyAuth, q.UserFindProductCategoryByID).
		Put("/:id", ownerKeyAuth, q.UserUpdateProductCategory)
	userSessionAuth := middleware.UserSessionAuth(q.sessionStore, q.accountUseCase)
	r.Get("", userSessionAuth, q.userIndex).
		Get("/new", userSessionAuth, q.userNew).
		Post("", userSessionAuth, q.userCreate).
		Get("/:id/edit", userSessionAuth, q.userEdit).
		Post("/:id", userSessionAuth, q.userUpdate)
}

func (q *productCategoryHTTPHandler) UserFindProductCategories(c *fiber.Ctx) error {
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

func (q *productCategoryHTTPHandler) UserCreateProductCategory(c *fiber.Ctx) error {
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
	response, err := q.productCategoryUseCase.CreateProductCategory(ctx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateProductCategory")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *productCategoryHTTPHandler) UserFindProductCategoryByID(c *fiber.Ctx) error {
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

func (q *productCategoryHTTPHandler) UserUpdateProductCategory(c *fiber.Ctx) error {
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
	productCategory := productCategories[0]
	if productCategory.Name == request.Name &&
		productCategory.Slug == request.Slug {
		return helper.NewResponse(fiber.StatusOK).SetData(productCategory).WriteResponse(c)
	}
	productCategory.Name = request.Name
	productCategory.Slug = request.Slug
	productCategory.UpdatedBy = currentUser.ID
	if err = q.productCategoryUseCase.UpdateProductCategory(ctx, productCategory); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProductCategory")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(productCategory).WriteResponse(c)
}

func (q *productCategoryHTTPHandler) userIndex(c *fiber.Ctx) error {
	ctxt := "ProductCategoryPresenter-userIndex"
	ctx := c.Context()
	sess, err := q.sessionStore.Get(c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGet")
		return c.Render("account/login", fiber.Map{
			"authenticated": false,
			"flash":         helper.NewFlashMessage().Danger(err.Error()),
			"request":       accountModel.LoginRequest{},
		})
	}
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
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
		})
	}
	defer flash.Clear(c, sess)
	return c.Render("product_category/index", fiber.Map{
		"authenticated": true,
		"currentUser":   currentUser,
		"flash":         flash,
		"q":             c.Query("q"),
		"rows":          rows,
		"pagination":    pagination,
		"limits":        models.Limits,
	})
}

func (q *productCategoryHTTPHandler) userNew(c *fiber.Ctx) error {
	ctxt := "ProductCategoryPresenter-userNew"
	ctx := c.Context()
	sess, err := q.sessionStore.Get(c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGet")
		return c.Render("account/login", fiber.Map{
			"authenticated": false,
			"flash":         helper.NewFlashMessage().Danger(err.Error()),
			"request":       accountModel.LoginRequest{},
		})
	}
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	request := new(productCategoryModel.ProductCategory)
	defer flash.Clear(c, sess)
	return c.Render("product_category/new", fiber.Map{
		"authenticated": true,
		"currentUser":   currentUser,
		"flash":         flash,
		"request":       request,
	})
}

func (q *productCategoryHTTPHandler) userCreate(c *fiber.Ctx) error {
	ctxt := "ProductCategoryPresenter-userCreate"
	ctx := c.Context()
	sess, err := q.sessionStore.Get(c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGet")
		return c.Render("account/login", fiber.Map{
			"authenticated": false,
			"flash":         helper.NewFlashMessage().Danger(err.Error()),
			"request":       accountModel.LoginRequest{},
		})
	}
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	request, statusCode, err := sanitizer.ValidateProductCategory(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateProductCategory")
		c.Response().SetStatusCode(statusCode)
		return c.Render("product_category/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
		})
	}
	request.CompanyID = currentUser.CompanyID
	request.CreatedBy = currentUser.ID
	if _, err = q.productCategoryUseCase.CreateProductCategory(ctx, request); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateProductCategory")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("product_category/new", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
		})
	}
	return flash.Success("category created successfully").Redirect(c, sess, "/product_category")
}

func (q *productCategoryHTTPHandler) userEdit(c *fiber.Ctx) error {
	ctxt := "ProductCategoryPresenter-userEdit"
	ctx := c.Context()
	sess, err := q.sessionStore.Get(c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGet")
		return c.Render("account/login", fiber.Map{
			"authenticated": false,
			"flash":         helper.NewFlashMessage().Danger(err.Error()),
			"request":       accountModel.LoginRequest{},
		})
	}
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
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
		})
	}
	if len(productCategories) == 0 {
		return flash.Danger("category not found").Redirect(c, sess, "/product_category")
	}
	defer flash.Clear(c, sess)
	return c.Render("product_category/edit", fiber.Map{
		"authenticated": true,
		"currentUser":   currentUser,
		"flash":         flash,
		"request":       productCategories[0],
	})
}

func (q *productCategoryHTTPHandler) userUpdate(c *fiber.Ctx) error {
	ctxt := "ProductCategoryPresenter-userUpdate"
	ctx := c.Context()
	sess, err := q.sessionStore.Get(c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGet")
		return c.Render("account/login", fiber.Map{
			"authenticated": false,
			"flash":         helper.NewFlashMessage().Danger(err.Error()),
			"request":       accountModel.LoginRequest{},
		})
	}
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	request, statusCode, err := sanitizer.ValidateProductCategory(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateProductCategory")
		c.Response().SetStatusCode(statusCode)
		return c.Render("product_category/edit", fiber.Map{
			"authenticated": true,
			"currentUser":   currentUser,
			"flash":         flash.Danger(err.Error()),
			"request":       request,
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
		})
	}
	if len(productCategories) == 0 {
		return flash.Danger("category not found").Redirect(c, sess, "/product_category")
	}
	productCategory := productCategories[0]
	if productCategory.Name != request.Name ||
		productCategory.Slug != request.Slug {
		productCategory.Name = request.Name
		productCategory.Slug = request.Slug
		productCategory.UpdatedBy = currentUser.ID
		if err = q.productCategoryUseCase.UpdateProductCategory(ctx, productCategory); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProductCategory")
			c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
			return c.Render("product_category/edit", fiber.Map{
				"authenticated": true,
				"currentUser":   currentUser,
				"flash":         flash.Danger(err.Error()),
				"request":       request,
			})
		}
	}
	return flash.Success("category updated successfully").Redirect(c, sess, "/product_category")
}
