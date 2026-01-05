package presenter

import (
	"strconv"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	companyUseCase "github.com/roysitumorang/sadia/modules/company/usecase"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	productModel "github.com/roysitumorang/sadia/modules/product/model"
	"github.com/roysitumorang/sadia/modules/product/sanitizer"
	productUseCase "github.com/roysitumorang/sadia/modules/product/usecase"
	productCategoryModel "github.com/roysitumorang/sadia/modules/product_category/model"
	productCategoryUseCase "github.com/roysitumorang/sadia/modules/product_category/usecase"
	sessionUseCase "github.com/roysitumorang/sadia/modules/session/usecase"
	transactionModel "github.com/roysitumorang/sadia/modules/transaction/model"
	"go.uber.org/zap"
)

type (
	productHTTPHandler struct {
		jwtUseCase             jwtUseCase.JwtUseCase
		accountUseCase         accountUseCase.AccountUseCase
		companyUseCase         companyUseCase.CompanyUseCase
		sessionUseCase         sessionUseCase.SessionUseCase
		productCategoryUseCase productCategoryUseCase.ProductCategoryUseCase
		productUseCase         productUseCase.ProductUseCase
	}
)

func New(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	companyUseCase companyUseCase.CompanyUseCase,
	sessionUseCase sessionUseCase.SessionUseCase,
	productCategoryUseCase productCategoryUseCase.ProductCategoryUseCase,
	productUseCase productUseCase.ProductUseCase,
) *productHTTPHandler {
	return &productHTTPHandler{
		jwtUseCase:             jwtUseCase,
		accountUseCase:         accountUseCase,
		companyUseCase:         companyUseCase,
		sessionUseCase:         sessionUseCase,
		productCategoryUseCase: productCategoryUseCase,
		productUseCase:         productUseCase,
	}
}

func (q *productHTTPHandler) Mount(r fiber.Router) {
	userKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase, q.companyUseCase, q.sessionUseCase)
	ownerKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase, q.companyUseCase, q.sessionUseCase, accountModel.UserLevelOwner)
	v1 := r.Group("/v1")
	v1.Get("", userKeyAuth, q.UserFindProducts).
		Post("", ownerKeyAuth, q.UserCreateProduct).
		Get("/:id", userKeyAuth, q.UserFindProductByID).
		Put("/:id", ownerKeyAuth, q.UserUpdateProduct)
	userSessionAuth := middleware.UserSessionAuth(q.accountUseCase, q.companyUseCase, q.sessionUseCase)
	r.Get("", userSessionAuth, q.userIndex).
		Get("/new", userSessionAuth, q.userNew).
		Post("", userSessionAuth, q.userCreate).
		Get("/:id/edit", userSessionAuth, q.userEdit).
		Post("/:id", userSessionAuth, q.userUpdate)
}

func (q *productHTTPHandler) UserFindProducts(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductPresenter-UserFindProducts"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	filter, err := sanitizer.FindProducts(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	filter.CompanyIDs = []int64{currentUser.CompanyID}
	rows, pagination, err := q.productUseCase.FindProducts(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *productHTTPHandler) UserCreateProduct(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductPresenter-UserCreateProduct"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	request, statusCode, err := sanitizer.ValidateProduct(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateProduct")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	if request.CategoryID != nil {
		productCategories, _, err := q.productCategoryUseCase.FindProductCategories(
			ctx,
			productCategoryModel.NewFilter(
				productCategoryModel.WithProductCategoryIDs(*request.CategoryID),
				productCategoryModel.WithCompanyIDs(currentUser.CompanyID),
			),
		)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProductCategories")
			return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
		}
		if len(productCategories) == 0 {
			return helper.NewResponse(fiber.StatusNotFound).SetMessage("category_id: not found").WriteResponse(c)
		}
	}
	request.CompanyID = currentUser.CompanyID
	request.CreatedBy = currentUser.ID
	response, err := q.productUseCase.CreateProduct(ctx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateProduct")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *productHTTPHandler) UserFindProductByID(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductPresenter-UserFindProductByID"
	productID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseInt")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	products, _, err := q.productUseCase.FindProducts(
		ctx,
		productModel.NewFilter(
			productModel.WithProductIDs(productID),
			productModel.WithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(products) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("product not found").WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(products[0]).WriteResponse(c)
}

func (q *productHTTPHandler) UserUpdateProduct(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductPresenter-UserUpdateProduct"
	productID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseInt")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	request, statusCode, err := sanitizer.ValidateProduct(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateProduct")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	if request.CategoryID != nil {
		productCategories, _, err := q.productCategoryUseCase.FindProductCategories(
			ctx,
			productCategoryModel.NewFilter(
				productCategoryModel.WithProductCategoryIDs(*request.CategoryID),
				productCategoryModel.WithCompanyIDs(currentUser.CompanyID),
			),
		)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProductCategories")
			return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
		}
		if len(productCategories) == 0 {
			return helper.NewResponse(fiber.StatusNotFound).SetMessage("category_id: not found").WriteResponse(c)
		}
	}
	products, _, err := q.productUseCase.FindProducts(
		ctx,
		productModel.NewFilter(
			productModel.WithProductIDs(productID),
			productModel.WithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(products) == 0 {
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("product not found").WriteResponse(c)
	}
	product := products[0]
	product.CategoryID = request.CategoryID
	product.Name = request.Name
	product.Code = request.Code
	product.UOM = request.UOM
	product.MinimumStock = request.MinimumStock
	product.Stock = request.Stock
	product.BasePrice = request.BasePrice
	product.SellingPrice = request.SellingPrice
	product.Weight = request.Weight
	product.RackPosition = request.RackPosition
	product.UpdatedBy = currentUser.ID
	if err = q.productUseCase.UpdateProduct(ctx, product); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProduct")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(product).WriteResponse(c)
}

func (q *productHTTPHandler) userIndex(c fiber.Ctx) error {
	ctxt := "ProductPresenter-userIndex"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	pagination := new(models.Pagination)
	var rows []*productModel.Product
	filter, err := sanitizer.FindProducts(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
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
		})
	}
	filter.CompanyIDs = []int64{currentUser.CompanyID}
	if rows, pagination, err = q.productUseCase.FindProducts(ctx, filter); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("product/index", fiber.Map{
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
	return c.Render("product/index", fiber.Map{
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

func (q *productHTTPHandler) userNew(c fiber.Ctx) error {
	ctxt := "ProductPresenter-userNew"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	request := new(productModel.Product)
	var categoryID string
	productCategories, _, err := q.productCategoryUseCase.FindProductCategories(
		ctx,
		productCategoryModel.NewFilter(
			productCategoryModel.WithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProductCategories")
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("product/new", fiber.Map{
			"authenticated":     true,
			"currentUser":       currentUser,
			"flash":             flash.Danger(err.Error()),
			"productCategories": productCategories,
			"request":           request,
			"categoryID":        categoryID,
			"cart":              cart,
		})
	}
	defer flash.Clear(c, sess.Session)
	return c.Render("product/new", fiber.Map{
		"authenticated":     true,
		"currentUser":       currentUser,
		"flash":             flash,
		"productCategories": productCategories,
		"request":           request,
		"categoryID":        categoryID,
		"cart":              cart,
	})
}

func (q *productHTTPHandler) userCreate(c fiber.Ctx) error {
	ctxt := "ProductPresenter-userCreate"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	var categoryID int64
	request, statusCode, errValidation := sanitizer.ValidateProduct(ctx, c)
	productCategories, _, err := q.productCategoryUseCase.FindProductCategories(
		ctx,
		productCategoryModel.NewFilter(
			productCategoryModel.WithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateProduct")
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("product/new", fiber.Map{
			"authenticated":     true,
			"currentUser":       currentUser,
			"flash":             flash.Danger(err.Error()),
			"productCategories": productCategories,
			"request":           request,
			"categoryID":        categoryID,
			"cart":              cart,
		})
	}
	if errValidation != nil {
		helper.Log(ctx, zap.ErrorLevel, errValidation.Error(), ctxt, "ErrValidateProduct")
		c.Response().SetStatusCode(statusCode)
		return c.Render("product/new", fiber.Map{
			"authenticated":     true,
			"currentUser":       currentUser,
			"flash":             flash.Danger(errValidation.Error()),
			"productCategories": productCategories,
			"request":           request,
			"categoryID":        categoryID,
			"cart":              cart,
		})
	}
	if request.CategoryID != nil {
		var found bool
		for _, category := range productCategories {
			if found = category.ID == *request.CategoryID; found {
				break
			}
		}
		if !found {
			c.Response().SetStatusCode(fiber.StatusNotFound)
			return c.Render("product/new", fiber.Map{
				"authenticated":     true,
				"currentUser":       currentUser,
				"flash":             flash.Danger("category_id: not found"),
				"productCategories": productCategories,
				"request":           request,
				"cart":              cart,
			})
		}
		categoryID = *request.CategoryID
	}
	request.CompanyID = currentUser.CompanyID
	request.CreatedBy = currentUser.ID
	if _, err = q.productUseCase.CreateProduct(ctx, request); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateProduct")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("product/new", fiber.Map{
			"authenticated":     true,
			"currentUser":       currentUser,
			"flash":             flash.Danger(err.Error()),
			"productCategories": productCategories,
			"request":           request,
			"categoryID":        categoryID,
			"cart":              cart,
		})
	}
	return flash.Success("product created successfully").Redirect(c, sess.Session, "/product")
}

func (q *productHTTPHandler) userEdit(c fiber.Ctx) error {
	ctxt := "ProductPresenter-userEdit"
	ctx := c.Context()
	sess := session.FromContext(c)
	productID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseInt")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	var categoryID int64
	products, _, err := q.productUseCase.FindProducts(
		ctx,
		productModel.NewFilter(
			productModel.WithProductIDs(productID),
			productModel.WithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
	}
	if len(products) == 0 {
		return flash.Danger("product not found").Redirect(c, sess.Session, "/product")
	}
	request := products[0]
	if request.CategoryID != nil {
		categoryID = *request.CategoryID
	}
	productCategories, _, err := q.productCategoryUseCase.FindProductCategories(
		ctx,
		productCategoryModel.NewFilter(
			productCategoryModel.WithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProductCategories")
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("product/edit", fiber.Map{
			"authenticated":     true,
			"currentUser":       currentUser,
			"flash":             flash.Danger(err.Error()),
			"productCategories": productCategories,
			"request":           request,
			"categoryID":        categoryID,
			"cart":              cart,
		})
	}
	defer flash.Clear(c, sess.Session)
	return c.Render("product/edit", fiber.Map{
		"authenticated":     true,
		"currentUser":       currentUser,
		"flash":             flash,
		"productCategories": productCategories,
		"request":           request,
		"categoryID":        categoryID,
		"cart":              cart,
	})
}

func (q *productHTTPHandler) userUpdate(c fiber.Ctx) error {
	ctxt := "ProductPresenter-userUpdate"
	ctx := c.Context()
	sess := session.FromContext(c)
	productID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseInt")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	var categoryID int64
	products, _, err := q.productUseCase.FindProducts(
		ctx,
		productModel.NewFilter(
			productModel.WithProductIDs(productID),
			productModel.WithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
	}
	if len(products) == 0 {
		return flash.Danger("product not found").Redirect(c, sess.Session, "/product")
	}
	request, statusCode, errValidation := sanitizer.ValidateProduct(ctx, c)
	if request.CategoryID != nil {
		categoryID = *request.CategoryID
	}
	productCategories, _, err := q.productCategoryUseCase.FindProductCategories(
		ctx,
		productCategoryModel.NewFilter(
			productCategoryModel.WithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateProduct")
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("product/edit", fiber.Map{
			"authenticated":     true,
			"currentUser":       currentUser,
			"flash":             flash.Danger(err.Error()),
			"productCategories": productCategories,
			"request":           request,
			"categoryID":        categoryID,
			"cart":              cart,
		})
	}
	if errValidation != nil {
		helper.Log(ctx, zap.ErrorLevel, errValidation.Error(), ctxt, "ErrValidateProduct")
		c.Response().SetStatusCode(statusCode)
		return c.Render("product/edit", fiber.Map{
			"authenticated":     true,
			"currentUser":       currentUser,
			"flash":             flash.Danger(errValidation.Error()),
			"productCategories": productCategories,
			"request":           request,
			"categoryID":        categoryID,
			"cart":              cart,
		})
	}
	if request.CategoryID != nil {
		var found bool
		for _, category := range productCategories {
			if found = category.ID == *request.CategoryID; found {
				break
			}
		}
		if !found {
			c.Response().SetStatusCode(fiber.StatusNotFound)
			return c.Render("product/edit", fiber.Map{
				"authenticated":     true,
				"currentUser":       currentUser,
				"flash":             flash.Danger("category_id: not found"),
				"productCategories": productCategories,
				"request":           request,
				"cart":              cart,
			})
		}
		categoryID = *request.CategoryID
	}
	product := products[0]
	var oldCategoryID, newCategoryID int64
	if product.CategoryID != nil {
		oldCategoryID = *product.CategoryID
	}
	if request.CategoryID != nil {
		newCategoryID = *request.CategoryID
	}
	if oldCategoryID != newCategoryID ||
		product.Name != request.Name ||
		product.Code != request.Code ||
		product.UOM != request.UOM ||
		product.MinimumStock != request.MinimumStock ||
		product.Stock != request.Stock ||
		product.BasePrice != request.BasePrice ||
		product.SellingPrice != request.SellingPrice ||
		product.Weight != request.Weight ||
		product.RackPosition != request.RackPosition {
		product.CategoryID = request.CategoryID
		product.Name = request.Name
		product.Code = request.Code
		product.UOM = request.UOM
		product.MinimumStock = request.MinimumStock
		product.Stock = request.Stock
		product.BasePrice = request.BasePrice
		product.SellingPrice = request.SellingPrice
		product.Weight = request.Weight
		product.RackPosition = request.RackPosition
		product.UpdatedBy = currentUser.ID
		if err = q.productUseCase.UpdateProduct(ctx, product); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProduct")
			c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
			return c.Render("product/edit", fiber.Map{
				"authenticated":     true,
				"currentUser":       currentUser,
				"flash":             flash.Danger("category_id: not found"),
				"productCategories": productCategories,
				"request":           request,
				"categoryID":        categoryID,
				"cart":              cart,
			})
		}
	}
	return flash.Success("product updated successfully").Redirect(c, sess.Session, "/product")
}
