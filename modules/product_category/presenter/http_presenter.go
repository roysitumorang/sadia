package presenter

import (
	"github.com/gofiber/fiber/v2"
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
		jwtUseCase             jwtUseCase.JwtUseCase
		accountUseCase         accountUseCase.AccountUseCase
		productCategoryUseCase productCategoryUseCase.ProductCategoryUseCase
	}
)

func New(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	productCategoryUseCase productCategoryUseCase.ProductCategoryUseCase,
) *productCategoryHTTPHandler {
	return &productCategoryHTTPHandler{
		jwtUseCase:             jwtUseCase,
		accountUseCase:         accountUseCase,
		productCategoryUseCase: productCategoryUseCase,
	}
}

func (q *productCategoryHTTPHandler) Mount(r fiber.Router) {
	userKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase)
	ownerKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase, accountModel.UserLevelOwner)
	r.Get("", userKeyAuth, q.UserFindProductCategories).
		Post("", ownerKeyAuth, q.UserCreateProductCategory).
		Get("/:id", userKeyAuth, q.UserFindProductCategoryByID).
		Put("/:id", ownerKeyAuth, q.UserUpdateProductCategory)
}

func (q *productCategoryHTTPHandler) UserFindProductCategories(c *fiber.Ctx) error {
	ctx := c.UserContext()
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
	ctx := c.UserContext()
	ctxt := "ProductCategoryPresenter-UserCreateProductCategory"
	currentUser, _ := c.Locals(models.CurrentUser).(*accountModel.User)
	request, statusCode, err := sanitizer.ValidateProductCategory(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidateProductCategory")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	request.CreatedBy = currentUser.ID
	response, err := q.productCategoryUseCase.CreateProductCategory(ctx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateProductCategory")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *productCategoryHTTPHandler) UserFindProductCategoryByID(c *fiber.Ctx) error {
	ctx := c.UserContext()
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
	ctx := c.UserContext()
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
	productCategory.Name = request.Name
	productCategory.Slug = request.Slug
	productCategory.UpdatedBy = currentUser.ID
	if err = q.productCategoryUseCase.UpdateProductCategory(ctx, productCategory); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProductCategory")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(productCategory).WriteResponse(c)
}
