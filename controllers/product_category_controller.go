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

type productCategoryController struct {
	jwtService             services.JwtService
	accountService         services.AccountService
	companyService         services.CompanyService
	sessionService         services.SessionService
	productCategoryService services.ProductCategoryService
	logService             services.LogService
}

func NewProductCategoryController(
	jwtService services.JwtService,
	accountService services.AccountService,
	companyService services.CompanyService,
	sessionService services.SessionService,
	productCategoryService services.ProductCategoryService,
	logService services.LogService,
) *productCategoryController {
	return &productCategoryController{
		jwtService:             jwtService,
		accountService:         accountService,
		companyService:         companyService,
		sessionService:         sessionService,
		productCategoryService: productCategoryService,
		logService:             logService,
	}
}

func (q *productCategoryController) Mount(r fiber.Router) {
	userKeyAuth := middleware.UserKeyAuth(q.jwtService, q.accountService, q.companyService, q.sessionService)
	ownerKeyAuth := middleware.UserKeyAuth(q.jwtService, q.accountService, q.companyService, q.sessionService, models.UserLevelOwner)
	v1 := r.Group("/v1")
	v1.Get("", userKeyAuth, q.UserFindProductCategories).
		Post("", ownerKeyAuth, q.UserCreateProductCategory).
		Get("/:id", userKeyAuth, q.UserFindProductCategoryByID).
		Put("/:id", ownerKeyAuth, q.UserUpdateProductCategory)
	userSessionAuth := middleware.UserSessionAuth(q.accountService, q.companyService, q.sessionService)
	r.Get("", userSessionAuth, q.userIndex).
		Get("/new", userSessionAuth, q.userNew).
		Post("", userSessionAuth, q.userCreate).
		Get("/:id/edit", userSessionAuth, q.userEdit).
		Post("/:id", userSessionAuth, q.userUpdate)
}

func (q *productCategoryController) UserFindProductCategories(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductCategoryController-UserFindProductCategories"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	filter, err := sanitizers.FindProductCategories(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProductCategories")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	filter.CompanyIDs = []uint64{currentUser.CompanyID}
	rows, pagination, err := q.productCategoryService.FindProductCategories(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindProductCategories")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(map[string]any{
		"pagination": pagination,
		"rows":       rows,
	}).WriteResponse(c)
}

func (q *productCategoryController) UserCreateProductCategory(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductCategoryController-UserCreateProductCategory"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	request, statusCode, err := sanitizers.ValidateProductCategory(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateProductCategory")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	request.CompanyID = currentUser.CompanyID
	request.CreatedBy = currentUser.ID
	request.CreatedAt = time.Now()
	tx, err := repositories.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response, err := q.productCategoryService.CreateProductCategory(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateProductCategory")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	log := &models.Log{
		CompanyID: currentUser.CompanyID,
		TableName: models.ProductCategoryTableName,
		TableID:   response.ID,
		Action:    models.ActionCreate,
		Changes: map[string]models.Change{
			"name": {New: response.Name},
			"slug": {New: response.Slug},
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

func (q *productCategoryController) UserFindProductCategoryByID(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductCategoryController-UserFindProductCategoryByID"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	productCategoryID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("category not found").WriteResponse(c)
	}
	productCategories, _, err := q.productCategoryService.FindProductCategories(
		ctx,
		models.NewProductCategoryFilter(
			models.ProductCategoryWithProductCategoryIDs(productCategoryID),
			models.ProductCategoryWithCompanyIDs(currentUser.CompanyID),
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

func (q *productCategoryController) UserUpdateProductCategory(c fiber.Ctx) error {
	ctx := c.Context()
	ctxt := "ProductCategoryController-UserUpdateProductCategory"
	currentUser, _ := c.Locals(models.CurrentUser).(*models.User)
	productCategoryID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return helper.NewResponse(fiber.StatusNotFound).SetMessage("category not found").WriteResponse(c)
	}
	request, statusCode, err := sanitizers.ValidateProductCategory(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateProductCategory")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	productCategories, _, err := q.productCategoryService.FindProductCategories(
		ctx,
		models.NewProductCategoryFilter(
			models.ProductCategoryWithProductCategoryIDs(productCategoryID),
			models.ProductCategoryWithCompanyIDs(currentUser.CompanyID),
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
	changes := map[string]models.Change{}
	nameChanged := existing.Name != request.Name
	if nameChanged {
		changes["name"] = models.Change{
			Old: existing.Name,
			New: request.Name,
		}
	}
	slugChanged := existing.Slug != request.Slug
	if slugChanged {
		changes["slug"] = models.Change{
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
	tx, err := repositories.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	saved, err := q.productCategoryService.UpdateProductCategory(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProductCategory")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	log := &models.Log{
		CompanyID: currentUser.CompanyID,
		TableName: models.ProductCategoryTableName,
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

func (q *productCategoryController) userIndex(c fiber.Ctx) error {
	ctxt := "ProductCategoryController-userIndex"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	pagination := new(models.Pagination)
	var rows []*models.ProductCategory
	filter, err := sanitizers.FindProductCategories(ctx, c)
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
	filter.CompanyIDs = []uint64{currentUser.CompanyID}
	if rows, pagination, err = q.productCategoryService.FindProductCategories(ctx, filter); err != nil {
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

func (q *productCategoryController) userNew(c fiber.Ctx) error {
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	request := new(models.ProductCategory)
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

func (q *productCategoryController) userCreate(c fiber.Ctx) error {
	ctxt := "ProductCategoryController-userCreate"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	request, statusCode, err := sanitizers.ValidateProductCategory(ctx, c)
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
	tx, err := repositories.BeginTx(ctx)
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
	productCategory, err := q.productCategoryService.CreateProductCategory(ctx, tx, request)
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
	log := &models.Log{
		CompanyID: currentUser.CompanyID,
		TableName: models.ProductCategoryTableName,
		TableID:   productCategory.ID,
		Action:    models.ActionCreate,
		Changes: map[string]models.Change{
			"name": {New: productCategory.Name},
			"slug": {New: productCategory.Slug},
		},
		CreatedBy: currentUser.ID,
		CreatedAt: productCategory.CreatedAt,
	}
	if _, err = q.logService.CreateLog(ctx, tx, log); err != nil {
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

func (q *productCategoryController) userEdit(c fiber.Ctx) error {
	ctxt := "ProductCategoryController-userEdit"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	productCategoryID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return flash.Danger("category not found").Redirect(c, sess.Session, "/product_category")
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	request := new(models.ProductCategory)
	productCategories, _, err := q.productCategoryService.FindProductCategories(
		ctx,
		models.NewProductCategoryFilter(
			models.ProductCategoryWithProductCategoryIDs(productCategoryID),
			models.ProductCategoryWithCompanyIDs(currentUser.CompanyID),
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

func (q *productCategoryController) userUpdate(c fiber.Ctx) error {
	ctxt := "ProductCategoryController-userUpdate"
	ctx := c.Context()
	sess := session.FromContext(c)
	currentUser := sess.Get(models.CurrentUser).(*models.User)
	flash, ok := sess.Get(helper.Flash).(*helper.FlashMessage)
	if !ok {
		flash = helper.NewFlashMessage()
	}
	productCategoryID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return flash.Danger("category not found").Redirect(c, sess.Session, "/product_category")
	}
	cart := sess.Get(models.CurrentCart).(*models.Transaction)
	request, statusCode, err := sanitizers.ValidateProductCategory(ctx, c)
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
	productCategories, _, err := q.productCategoryService.FindProductCategories(
		ctx,
		models.NewProductCategoryFilter(
			models.ProductCategoryWithProductCategoryIDs(productCategoryID),
			models.ProductCategoryWithCompanyIDs(currentUser.CompanyID),
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
	changes := map[string]models.Change{}
	nameChanged := existing.Name != request.Name
	if nameChanged {
		changes["name"] = models.Change{
			Old: existing.Name,
			New: request.Name,
		}
	}
	slugChanged := existing.Slug != request.Slug
	if slugChanged {
		changes["slug"] = models.Change{
			Old: existing.Slug,
			New: request.Slug,
		}
	}
	if nameChanged || slugChanged {
		request.ID = existing.ID
		request.UpdatedBy = currentUser.ID
		request.UpdatedAt = time.Now()
		tx, err := repositories.BeginTx(ctx)
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
		saved, err := q.productCategoryService.UpdateProductCategory(ctx, tx, request)
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
		log := &models.Log{
			CompanyID: currentUser.CompanyID,
			TableName: models.ProductCategoryTableName,
			TableID:   saved.ID,
			Action:    models.ActionUpdate,
			Changes:   changes,
			CreatedBy: currentUser.ID,
			CreatedAt: saved.UpdatedAt,
		}
		if _, err = q.logService.CreateLog(ctx, tx, log); err != nil {
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
