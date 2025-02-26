package presenter

import (
	"github.com/gofiber/fiber/v2"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	productModel "github.com/roysitumorang/sadia/modules/product/model"
	"github.com/roysitumorang/sadia/modules/product/sanitizer"
	productUseCase "github.com/roysitumorang/sadia/modules/product/usecase"
	productCategoryModel "github.com/roysitumorang/sadia/modules/product_category/model"
	productCategoryUseCase "github.com/roysitumorang/sadia/modules/product_category/usecase"
	"go.uber.org/zap"
)

type (
	productHTTPHandler struct {
		jwtUseCase             jwtUseCase.JwtUseCase
		accountUseCase         accountUseCase.AccountUseCase
		productCategoryUseCase productCategoryUseCase.ProductCategoryUseCase
		productUseCase         productUseCase.ProductUseCase
	}
)

func New(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	productCategoryUseCase productCategoryUseCase.ProductCategoryUseCase,
	productUseCase productUseCase.ProductUseCase,
) *productHTTPHandler {
	return &productHTTPHandler{
		jwtUseCase:             jwtUseCase,
		accountUseCase:         accountUseCase,
		productCategoryUseCase: productCategoryUseCase,
		productUseCase:         productUseCase,
	}
}

func (q *productHTTPHandler) Mount(r fiber.Router) {
	userKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase)
	ownerKeyAuth := middleware.UserKeyAuth(q.jwtUseCase, q.accountUseCase, accountModel.UserLevelOwner)
	r.Get("", userKeyAuth, q.UserFindProducts).
		Post("", ownerKeyAuth, q.UserCreateProduct).
		Get("/:id", userKeyAuth, q.UserFindProductByID).
		Put("/:id", ownerKeyAuth, q.UserUpdateProduct)
}

func (q *productHTTPHandler) UserFindProducts(c *fiber.Ctx) error {
	ctx := c.UserContext()
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

func (q *productHTTPHandler) UserCreateProduct(c *fiber.Ctx) error {
	ctx := c.UserContext()
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
			return helper.NewResponse(fiber.StatusNotFound).SetMessage("category not found").WriteResponse(c)
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

func (q *productHTTPHandler) UserFindProductByID(c *fiber.Ctx) error {
	ctx := c.UserContext()
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

func (q *productHTTPHandler) UserUpdateProduct(c *fiber.Ctx) error {
	ctx := c.UserContext()
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
			return helper.NewResponse(fiber.StatusNotFound).SetMessage("category not found").WriteResponse(c)
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
	product := products[0]
	product.CategoryID = request.CategoryID
	product.Name = request.Name
	product.Slug = request.Slug
	product.UOM = request.UOM
	product.Stock = request.Stock
	product.Price = request.Price
	product.UpdatedBy = currentUser.ID
	if err = q.productUseCase.UpdateProduct(ctx, product); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateProduct")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	return helper.NewResponse(fiber.StatusOK).SetData(product).WriteResponse(c)
}
