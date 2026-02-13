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
	companyModel "github.com/roysitumorang/sadia/modules/company/model"
	companyUseCase "github.com/roysitumorang/sadia/modules/company/usecase"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	logModel "github.com/roysitumorang/sadia/modules/log/model"
	logUseCase "github.com/roysitumorang/sadia/modules/log/usecase"
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
		logUseCase             logUseCase.LogUseCase
	}
)

func New(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	companyUseCase companyUseCase.CompanyUseCase,
	sessionUseCase sessionUseCase.SessionUseCase,
	productCategoryUseCase productCategoryUseCase.ProductCategoryUseCase,
	productUseCase productUseCase.ProductUseCase,
	logUseCase logUseCase.LogUseCase,
) *productHTTPHandler {
	return &productHTTPHandler{
		jwtUseCase:             jwtUseCase,
		accountUseCase:         accountUseCase,
		companyUseCase:         companyUseCase,
		sessionUseCase:         sessionUseCase,
		productCategoryUseCase: productCategoryUseCase,
		productUseCase:         productUseCase,
		logUseCase:             logUseCase,
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
	filter.CompanyIDs = []string{currentUser.CompanyID}
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
	request.CreatedAt = time.Now()
	tx, err := helper.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response, err := q.productUseCase.CreateProduct(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateProduct")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	log := &logModel.Log{
		CompanyID: currentUser.CompanyID,
		TableName: productModel.TableName,
		TableID:   response.ID,
		Action:    logModel.ActionCreate,
		Changes: map[string]logModel.Change{
			"category_id":   {New: response.CategoryID},
			"name":          {New: response.Name},
			"code":          {New: response.Code},
			"uom":           {New: response.UOM},
			"minimum_stock": {New: response.MinimumStock},
			"stock":         {New: response.Stock},
			"base_price":    {New: response.BasePrice},
			"selling_price": {New: response.SellingPrice},
			"weight":        {New: response.Weight},
			"rack_position": {New: response.RackPosition},
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

func (q *productHTTPHandler) UserFindProductByID(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductPresenter-UserFindProductByID"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	products, _, err := q.productUseCase.FindProducts(
		ctx,
		productModel.NewFilter(
			productModel.WithProductIDs(c.Params("id")),
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
			productModel.WithProductIDs(c.Params("id")),
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
	existing := products[0]
	changes := map[string]logModel.Change{}
	var oldCategoryID, newCategoryID string
	if existing.CategoryID != nil {
		oldCategoryID = *existing.CategoryID
	}
	if request.CategoryID != nil {
		newCategoryID = *request.CategoryID
	}
	categoryChanged := oldCategoryID != newCategoryID
	if categoryChanged {
		changes["category_id"] = logModel.Change{
			Old: existing.CategoryID,
			New: request.CategoryID,
		}
	}
	nameChanged := existing.Name != request.Name
	if nameChanged {
		changes["name"] = logModel.Change{
			Old: existing.Name,
			New: request.Name,
		}
	}
	codeChanged := existing.Code != request.Code
	if codeChanged {
		changes["code"] = logModel.Change{
			Old: existing.Code,
			New: request.Code,
		}
	}
	uomChanged := existing.UOM != request.UOM
	if uomChanged {
		changes["uom"] = logModel.Change{
			Old: existing.UOM,
			New: request.UOM,
		}
	}
	minimumStockChanged := existing.MinimumStock != request.MinimumStock
	if minimumStockChanged {
		changes["minimum_stock"] = logModel.Change{
			Old: existing.MinimumStock,
			New: request.MinimumStock,
		}
	}
	stockChanged := existing.Stock != request.Stock
	if stockChanged {
		changes["stock"] = logModel.Change{
			Old: existing.Stock,
			New: request.Stock,
		}
	}
	basePriceChanged := existing.BasePrice != request.BasePrice
	if basePriceChanged {
		changes["base_price"] = logModel.Change{
			Old: existing.BasePrice,
			New: request.BasePrice,
		}
	}
	sellingPriceChanged := existing.SellingPrice != request.SellingPrice
	if sellingPriceChanged {
		changes["selling_price"] = logModel.Change{
			Old: existing.SellingPrice,
			New: request.SellingPrice,
		}
	}
	weightChanged := existing.Weight != request.Weight
	if weightChanged {
		changes["weight"] = logModel.Change{
			Old: existing.Weight,
			New: request.Weight,
		}
	}
	rackPositionChanged := existing.RackPosition != request.RackPosition
	if rackPositionChanged {
		changes["rack_position"] = logModel.Change{
			Old: existing.RackPosition,
			New: request.RackPosition,
		}
	}
	if !categoryChanged &&
		!nameChanged &&
		!codeChanged &&
		!uomChanged &&
		!minimumStockChanged &&
		!stockChanged &&
		!basePriceChanged &&
		!sellingPriceChanged &&
		!weightChanged &&
		!rackPositionChanged {
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
	saved, err := q.productUseCase.UpdateProduct(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProduct")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	log := &logModel.Log{
		CompanyID: currentUser.CompanyID,
		TableName: productModel.TableName,
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

func (q *productHTTPHandler) userIndex(c fiber.Ctx) error {
	ctxt := "ProductPresenter-userIndex"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	currentCompany := sess.Get(models.CurrentCompany).(*companyModel.Company)
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
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash.Danger(err.Error()),
			"q":              c.Query("q"),
			"rows":           rows,
			"pagination":     pagination,
			"limits":         models.Limits,
			"cart":           cart,
			"path":           c.Route().Path,
			"currentCompany": currentCompany,
		})
	}
	filter.CompanyIDs = []string{currentUser.CompanyID}
	if rows, pagination, err = q.productUseCase.FindProducts(ctx, filter); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
		c.Response().SetStatusCode(fiber.StatusBadRequest)
		return c.Render("product/index", fiber.Map{
			"authenticated":  true,
			"currentUser":    currentUser,
			"flash":          flash.Danger(err.Error()),
			"q":              c.Query("q"),
			"rows":           rows,
			"pagination":     pagination,
			"limits":         models.Limits,
			"cart":           cart,
			"path":           c.Route().Path,
			"currentCompany": currentCompany,
		})
	}
	defer flash.Clear(c, sess.Session)
	return c.Render("product/index", fiber.Map{
		"authenticated":  true,
		"currentUser":    currentUser,
		"flash":          flash,
		"q":              c.Query("q"),
		"rows":           rows,
		"pagination":     pagination,
		"limits":         models.Limits,
		"cart":           cart,
		"path":           c.Route().Path,
		"currentCompany": currentCompany,
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
			"path":              c.Route().Path,
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
		"path":              c.Route().Path,
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
	var categoryID string
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
			"path":              c.Route().Path,
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
			"path":              c.Route().Path,
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
				"path":              c.Route().Path,
			})
		}
		categoryID = *request.CategoryID
	}
	request.CompanyID = currentUser.CompanyID
	request.CreatedBy = currentUser.ID
	request.CreatedAt = time.Now()
	tx, err := helper.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("product/new", fiber.Map{
			"authenticated":     true,
			"currentUser":       currentUser,
			"flash":             flash.Danger(err.Error()),
			"productCategories": productCategories,
			"request":           request,
			"categoryID":        categoryID,
			"cart":              cart,
			"path":              c.Route().Path,
		})
	}
	response, err := q.productUseCase.CreateProduct(ctx, tx, request)
	if err != nil {
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
			"path":              c.Route().Path,
		})
	}
	log := &logModel.Log{
		CompanyID: currentUser.CompanyID,
		TableName: productModel.TableName,
		TableID:   response.ID,
		Action:    logModel.ActionCreate,
		Changes: map[string]logModel.Change{
			"category_id":   {New: response.CategoryID},
			"name":          {New: response.Name},
			"code":          {New: response.Code},
			"uom":           {New: response.UOM},
			"minimum_stock": {New: response.MinimumStock},
			"stock":         {New: response.Stock},
			"base_price":    {New: response.BasePrice},
			"selling_price": {New: response.SellingPrice},
			"weight":        {New: response.Weight},
			"rack_position": {New: response.RackPosition},
		},
		CreatedBy: response.CreatedBy,
		CreatedAt: response.CreatedAt,
	}
	if _, err = q.logUseCase.CreateLog(ctx, tx, log); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateLog")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("product/new", fiber.Map{
			"authenticated":     true,
			"currentUser":       currentUser,
			"flash":             flash.Danger(err.Error()),
			"productCategories": productCategories,
			"request":           request,
			"categoryID":        categoryID,
			"cart":              cart,
			"path":              c.Route().Path,
		})
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
		return c.Render("product/new", fiber.Map{
			"authenticated":     true,
			"currentUser":       currentUser,
			"flash":             flash.Danger(err.Error()),
			"productCategories": productCategories,
			"request":           request,
			"categoryID":        categoryID,
			"cart":              cart,
			"path":              c.Route().Path,
		})
	}
	return flash.Clear(c, sess.Session).Success("product created successfully").Redirect(c, sess.Session, "/product")
}

func (q *productHTTPHandler) userEdit(c fiber.Ctx) error {
	ctxt := "ProductPresenter-userEdit"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	var categoryID string
	products, _, err := q.productUseCase.FindProducts(
		ctx,
		productModel.NewFilter(
			productModel.WithProductIDs(c.Params("id")),
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
			"path":              c.Route().Path,
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
		"path":              c.Route().Path,
	})
}

func (q *productHTTPHandler) userUpdate(c fiber.Ctx) error {
	ctxt := "ProductPresenter-userUpdate"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*accountModel.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(transactionModel.CurrentCart).(*transactionModel.Transaction)
	var categoryID string
	products, _, err := q.productUseCase.FindProducts(
		ctx,
		productModel.NewFilter(
			productModel.WithProductIDs(c.Params("id")),
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
			"path":              c.Route().Path,
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
			"path":              c.Route().Path,
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
				"path":              c.Route().Path,
			})
		}
		categoryID = *request.CategoryID
	}
	existing := products[0]
	changes := map[string]logModel.Change{}
	var oldCategoryID, newCategoryID string
	if existing.CategoryID != nil {
		oldCategoryID = *existing.CategoryID
	}
	if request.CategoryID != nil {
		newCategoryID = *request.CategoryID
	}
	categoryChanged := oldCategoryID != newCategoryID
	if categoryChanged {
		changes["category_id"] = logModel.Change{
			Old: existing.CategoryID,
			New: request.CategoryID,
		}
	}
	nameChanged := existing.Name != request.Name
	if nameChanged {
		changes["name"] = logModel.Change{
			Old: existing.Name,
			New: request.Name,
		}
	}
	codeChanged := existing.Code != request.Code
	if codeChanged {
		changes["code"] = logModel.Change{
			Old: existing.Code,
			New: request.Code,
		}
	}
	uomChanged := existing.UOM != request.UOM
	if uomChanged {
		changes["uom"] = logModel.Change{
			Old: existing.UOM,
			New: request.UOM,
		}
	}
	minimumStockChanged := existing.MinimumStock != request.MinimumStock
	if minimumStockChanged {
		changes["minimum_stock"] = logModel.Change{
			Old: existing.MinimumStock,
			New: request.MinimumStock,
		}
	}
	stockChanged := existing.Stock != request.Stock
	if stockChanged {
		changes["stock"] = logModel.Change{
			Old: existing.Stock,
			New: request.Stock,
		}
	}
	basePriceChanged := existing.BasePrice != request.BasePrice
	if basePriceChanged {
		changes["base_price"] = logModel.Change{
			Old: existing.BasePrice,
			New: request.BasePrice,
		}
	}
	sellingPriceChanged := existing.SellingPrice != request.SellingPrice
	if sellingPriceChanged {
		changes["selling_price"] = logModel.Change{
			Old: existing.SellingPrice,
			New: request.SellingPrice,
		}
	}
	weightChanged := existing.Weight != request.Weight
	if weightChanged {
		changes["weight"] = logModel.Change{
			Old: existing.Weight,
			New: request.Weight,
		}
	}
	rackPositionChanged := existing.RackPosition != request.RackPosition
	if rackPositionChanged {
		changes["rack_position"] = logModel.Change{
			Old: existing.RackPosition,
			New: request.RackPosition,
		}
	}
	if categoryChanged ||
		nameChanged ||
		codeChanged ||
		uomChanged ||
		minimumStockChanged ||
		stockChanged ||
		basePriceChanged ||
		sellingPriceChanged ||
		weightChanged ||
		rackPositionChanged {
		request.ID = existing.ID
		request.UpdatedBy = currentUser.ID
		request.UpdatedAt = time.Now()
		tx, err := helper.BeginTx(ctx)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
			c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
			return c.Render("product/edit", fiber.Map{
				"authenticated":     true,
				"currentUser":       currentUser,
				"flash":             flash.Danger(err.Error()),
				"productCategories": productCategories,
				"request":           request,
				"categoryID":        categoryID,
				"cart":              cart,
				"path":              c.Route().Path,
			})
		}
		saved, err := q.productUseCase.UpdateProduct(ctx, tx, request)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProduct")
			c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
			return c.Render("product/edit", fiber.Map{
				"authenticated":     true,
				"currentUser":       currentUser,
				"flash":             flash.Danger(err.Error()),
				"productCategories": productCategories,
				"request":           request,
				"categoryID":        categoryID,
				"cart":              cart,
				"path":              c.Route().Path,
			})
		}
		log := &logModel.Log{
			CompanyID: currentUser.CompanyID,
			TableName: productModel.TableName,
			TableID:   saved.ID,
			Action:    logModel.ActionUpdate,
			Changes:   changes,
			CreatedBy: saved.CreatedBy,
			CreatedAt: saved.UpdatedAt,
		}
		if _, err = q.logUseCase.CreateLog(ctx, tx, log); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateLog")
			c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
			return c.Render("product/edit", fiber.Map{
				"authenticated":     true,
				"currentUser":       currentUser,
				"flash":             flash.Danger(err.Error()),
				"productCategories": productCategories,
				"request":           request,
				"categoryID":        categoryID,
				"cart":              cart,
				"path":              c.Route().Path,
			})
		}
		if err = tx.Commit(ctx); err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
			c.Response().SetStatusCode(fiber.StatusUnprocessableEntity)
			return c.Render("product/edit", fiber.Map{
				"authenticated":     true,
				"currentUser":       currentUser,
				"flash":             flash.Danger(err.Error()),
				"productCategories": productCategories,
				"request":           request,
				"categoryID":        categoryID,
				"cart":              cart,
				"path":              c.Route().Path,
			})
		}
	}
	return flash.Clear(c, sess.Session).Success("product updated successfully").Redirect(c, sess.Session, "/product")
}
