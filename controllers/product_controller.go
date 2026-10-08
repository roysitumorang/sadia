package controllers

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/repositories"
	"github.com/roysitumorang/sadia/sanitizers"
	"github.com/roysitumorang/sadia/services"
	"go.uber.org/zap"
)

type productController struct {
	jwtService             services.JwtService
	accountService         services.AccountService
	companyService         services.CompanyService
	sessionService         services.SessionService
	productCategoryService services.ProductCategoryService
	productService         services.ProductService
	logService             services.LogService
}

func NewProductController(
	jwtService services.JwtService,
	accountService services.AccountService,
	companyService services.CompanyService,
	sessionService services.SessionService,
	productCategoryService services.ProductCategoryService,
	productService services.ProductService,
	logService services.LogService,
) *productController {
	return &productController{
		jwtService:             jwtService,
		accountService:         accountService,
		companyService:         companyService,
		sessionService:         sessionService,
		productCategoryService: productCategoryService,
		productService:         productService,
		logService:             logService,
	}
}

func (q *productController) Mount(r fiber.Router) {
	userKeyAuth := middleware.UserKeyAuth(q.jwtService, q.accountService, q.companyService, q.sessionService)
	ownerKeyAuth := middleware.UserKeyAuth(q.jwtService, q.accountService, q.companyService, q.sessionService, models.UserLevelOwner)
	v1 := r.Group("/v1")
	v1.Get("", userKeyAuth, q.UserFindProducts).
		Post("", ownerKeyAuth, q.UserCreateProduct).
		Get("/:id", userKeyAuth, q.UserFindProductByID).
		Put("/:id", ownerKeyAuth, q.UserUpdateProduct)
	userSessionAuth := middleware.UserSessionAuth(q.accountService, q.companyService, q.sessionService)
	r.Get("", userSessionAuth, q.userIndex).
		Get("/new", userSessionAuth, q.userNew).
		Post("", userSessionAuth, q.userCreate).
		Get("/:id/edit", userSessionAuth, q.userEdit).
		Post("/:id", userSessionAuth, q.userUpdate)
}

func (q *productController) UserFindProducts(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductPresenter-UserFindProducts"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	filter, err := sanitizers.FindProducts(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	filter.CompanyIDs = []uint64{currentUser.CompanyID}
	rows, pagination, err := q.productService.FindProducts(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *productController) UserCreateProduct(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductPresenter-UserCreateProduct"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	request, statusCode, err := sanitizers.ValidateProduct(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateProduct")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	if request.CategoryID != nil {
		productCategories, _, err := q.productCategoryService.FindProductCategories(
			ctx,
			models.NewProductCategoryFilter(
				models.ProductCategoryWithProductCategoryIDs(*request.CategoryID),
				models.ProductCategoryWithCompanyIDs(currentUser.CompanyID),
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
	tx, err := repositories.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response, err := q.productService.CreateProduct(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateProduct")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	log := &models.Log{
		CompanyID: currentUser.CompanyID,
		TableName: models.ProductTableName,
		TableID:   response.ID,
		Action:    models.ActionCreate,
		Changes: map[string]models.Change{
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
	if _, err = q.logService.CreateLog(ctx, tx, log); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateLog")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *productController) UserFindProductByID(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductPresenter-UserFindProductByID"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	productID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("product not found").WriteResponse(c)
	}
	products, _, err := q.productService.FindProducts(
		ctx,
		models.NewProductFilter(
			models.ProductWithProductIDs(productID),
			models.ProductWithCompanyIDs(currentUser.CompanyID),
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

func (q *productController) UserUpdateProduct(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductPresenter-UserUpdateProduct"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	productID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("product not found").WriteResponse(c)
	}
	request, statusCode, err := sanitizers.ValidateProduct(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateProduct")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	if request.CategoryID != nil {
		productCategories, _, err := q.productCategoryService.FindProductCategories(
			ctx,
			models.NewProductCategoryFilter(
				models.ProductCategoryWithProductCategoryIDs(*request.CategoryID),
				models.ProductCategoryWithCompanyIDs(currentUser.CompanyID),
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
	products, _, err := q.productService.FindProducts(
		ctx,
		models.NewProductFilter(
			models.ProductWithProductIDs(productID),
			models.ProductWithCompanyIDs(currentUser.CompanyID),
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
	changes := map[string]models.Change{}
	var oldCategoryID, newCategoryID uint64
	if existing.CategoryID != nil {
		oldCategoryID = *existing.CategoryID
	}
	if request.CategoryID != nil {
		newCategoryID = *request.CategoryID
	}
	categoryChanged := oldCategoryID != newCategoryID
	if categoryChanged {
		changes["category_id"] = models.Change{
			Old: existing.CategoryID,
			New: request.CategoryID,
		}
	}
	nameChanged := existing.Name != request.Name
	if nameChanged {
		changes["name"] = models.Change{
			Old: existing.Name,
			New: request.Name,
		}
	}
	codeChanged := existing.Code != request.Code
	if codeChanged {
		changes["code"] = models.Change{
			Old: existing.Code,
			New: request.Code,
		}
	}
	uomChanged := existing.UOM != request.UOM
	if uomChanged {
		changes["uom"] = models.Change{
			Old: existing.UOM,
			New: request.UOM,
		}
	}
	minimumStockChanged := existing.MinimumStock != request.MinimumStock
	if minimumStockChanged {
		changes["minimum_stock"] = models.Change{
			Old: existing.MinimumStock,
			New: request.MinimumStock,
		}
	}
	stockChanged := existing.Stock != request.Stock
	if stockChanged {
		changes["stock"] = models.Change{
			Old: existing.Stock,
			New: request.Stock,
		}
	}
	basePriceChanged := existing.BasePrice != request.BasePrice
	if basePriceChanged {
		changes["base_price"] = models.Change{
			Old: existing.BasePrice,
			New: request.BasePrice,
		}
	}
	sellingPriceChanged := existing.SellingPrice != request.SellingPrice
	if sellingPriceChanged {
		changes["selling_price"] = models.Change{
			Old: existing.SellingPrice,
			New: request.SellingPrice,
		}
	}
	weightChanged := existing.Weight != request.Weight
	if weightChanged {
		changes["weight"] = models.Change{
			Old: existing.Weight,
			New: request.Weight,
		}
	}
	rackPositionChanged := existing.RackPosition != request.RackPosition
	if rackPositionChanged {
		changes["rack_position"] = models.Change{
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
	tx, err := repositories.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	saved, err := q.productService.UpdateProduct(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProduct")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	log := &models.Log{
		CompanyID: currentUser.CompanyID,
		TableName: models.ProductTableName,
		TableID:   saved.ID,
		Action:    models.ActionUpdate,
		Changes:   changes,
		CreatedBy: saved.CreatedBy,
		CreatedAt: saved.UpdatedAt,
	}
	if _, err = q.logService.CreateLog(ctx, tx, log); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateLog")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(saved).WriteResponse(c)
}

func (q *productController) userIndex(c fiber.Ctx) error {
	ctxt := "ProductPresenter-userIndex"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	currentCompany := sess.Get(models.CurrentCompany).(*models.Company)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	pagination := new(models.Pagination)
	var rows []*models.Product
	filter, err := sanitizers.FindProducts(ctx, c)
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
	filter.CompanyIDs = []uint64{currentUser.CompanyID}
	if rows, pagination, err = q.productService.FindProducts(ctx, filter); err != nil {
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

func (q *productController) userNew(c fiber.Ctx) error {
	ctxt := "ProductPresenter-userNew"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	request := new(models.Product)
	var categoryID string
	productCategories, _, err := q.productCategoryService.FindProductCategories(
		ctx,
		models.NewProductCategoryFilter(
			models.ProductCategoryWithCompanyIDs(currentUser.CompanyID),
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

func (q *productController) userCreate(c fiber.Ctx) error {
	ctxt := "ProductPresenter-userCreate"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	var categoryID uint64
	request, statusCode, errValidation := sanitizers.ValidateProduct(ctx, c)
	productCategories, _, err := q.productCategoryService.FindProductCategories(
		ctx,
		models.NewProductCategoryFilter(
			models.ProductCategoryWithCompanyIDs(currentUser.CompanyID),
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
	tx, err := repositories.BeginTx(ctx)
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
	response, err := q.productService.CreateProduct(ctx, tx, request)
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
	log := &models.Log{
		CompanyID: currentUser.CompanyID,
		TableName: models.ProductTableName,
		TableID:   response.ID,
		Action:    models.ActionCreate,
		Changes: map[string]models.Change{
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
	if _, err = q.logService.CreateLog(ctx, tx, log); err != nil {
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

func (q *productController) userEdit(c fiber.Ctx) error {
	ctxt := "ProductPresenter-userEdit"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	productID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return flash.Danger("product not found").Redirect(c, sess.Session, "/product")
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	var categoryID uint64
	products, _, err := q.productService.FindProducts(
		ctx,
		models.NewProductFilter(
			models.ProductWithProductIDs(productID),
			models.ProductWithCompanyIDs(currentUser.CompanyID),
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
	productCategories, _, err := q.productCategoryService.FindProductCategories(
		ctx,
		models.NewProductCategoryFilter(
			models.ProductCategoryWithCompanyIDs(currentUser.CompanyID),
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

func (q *productController) userUpdate(c fiber.Ctx) error {
	ctxt := "ProductPresenter-userUpdate"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	productID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return flash.Danger("product not found").Redirect(c, sess.Session, "/product")
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	var categoryID uint64
	products, _, err := q.productService.FindProducts(
		ctx,
		models.NewProductFilter(
			models.ProductWithProductIDs(productID),
			models.ProductWithCompanyIDs(currentUser.CompanyID),
		),
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProducts")
	}
	if len(products) == 0 {
		return flash.Danger("product not found").Redirect(c, sess.Session, "/product")
	}
	request, statusCode, errValidation := sanitizers.ValidateProduct(ctx, c)
	if request.CategoryID != nil {
		categoryID = *request.CategoryID
	}
	productCategories, _, err := q.productCategoryService.FindProductCategories(
		ctx,
		models.NewProductCategoryFilter(
			models.ProductCategoryWithCompanyIDs(currentUser.CompanyID),
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
	changes := map[string]models.Change{}
	var oldCategoryID, newCategoryID uint64
	if existing.CategoryID != nil {
		oldCategoryID = *existing.CategoryID
	}
	if request.CategoryID != nil {
		newCategoryID = *request.CategoryID
	}
	categoryChanged := oldCategoryID != newCategoryID
	if categoryChanged {
		changes["category_id"] = models.Change{
			Old: existing.CategoryID,
			New: request.CategoryID,
		}
	}
	nameChanged := existing.Name != request.Name
	if nameChanged {
		changes["name"] = models.Change{
			Old: existing.Name,
			New: request.Name,
		}
	}
	codeChanged := existing.Code != request.Code
	if codeChanged {
		changes["code"] = models.Change{
			Old: existing.Code,
			New: request.Code,
		}
	}
	uomChanged := existing.UOM != request.UOM
	if uomChanged {
		changes["uom"] = models.Change{
			Old: existing.UOM,
			New: request.UOM,
		}
	}
	minimumStockChanged := existing.MinimumStock != request.MinimumStock
	if minimumStockChanged {
		changes["minimum_stock"] = models.Change{
			Old: existing.MinimumStock,
			New: request.MinimumStock,
		}
	}
	stockChanged := existing.Stock != request.Stock
	if stockChanged {
		changes["stock"] = models.Change{
			Old: existing.Stock,
			New: request.Stock,
		}
	}
	basePriceChanged := existing.BasePrice != request.BasePrice
	if basePriceChanged {
		changes["base_price"] = models.Change{
			Old: existing.BasePrice,
			New: request.BasePrice,
		}
	}
	sellingPriceChanged := existing.SellingPrice != request.SellingPrice
	if sellingPriceChanged {
		changes["selling_price"] = models.Change{
			Old: existing.SellingPrice,
			New: request.SellingPrice,
		}
	}
	weightChanged := existing.Weight != request.Weight
	if weightChanged {
		changes["weight"] = models.Change{
			Old: existing.Weight,
			New: request.Weight,
		}
	}
	rackPositionChanged := existing.RackPosition != request.RackPosition
	if rackPositionChanged {
		changes["rack_position"] = models.Change{
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
		tx, err := repositories.BeginTx(ctx)
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
		saved, err := q.productService.UpdateProduct(ctx, tx, request)
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
		log := &models.Log{
			CompanyID: currentUser.CompanyID,
			TableName: models.ProductTableName,
			TableID:   saved.ID,
			Action:    models.ActionUpdate,
			Changes:   changes,
			CreatedBy: saved.CreatedBy,
			CreatedAt: saved.UpdatedAt,
		}
		if _, err = q.logService.CreateLog(ctx, tx, log); err != nil {
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
