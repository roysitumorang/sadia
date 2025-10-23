package sanitizer

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/roysitumorang/sadia/helper"
	productCategoryModel "github.com/roysitumorang/sadia/modules/product_category/model"
	"go.uber.org/zap"
)

func FindProductCategories(ctx context.Context, c fiber.Ctx) (*productCategoryModel.Filter, error) {
	ctxt := "ProductCategorySanitizer-FindProductCategories"
	originalURL, err := url.ParseRequestURI(helper.ByteSlice2String(c.Request().URI().FullURI()))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseRequestURI")
		return nil, err
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(originalURL.Path)
	urlValues := originalURL.Query()
	var options []productCategoryModel.FilterOption
	options = append(options, productCategoryModel.WithPaginationURL(builder.String()))
	if keyword := strings.TrimSpace(c.Query("q")); keyword != "" {
		urlValues.Set("q", keyword)
		options = append(options, productCategoryModel.WithKeyword(keyword))
	}
	limitMin, limitMax := helper.GetPaginationLimit()
	limit, _ := strconv.ParseInt(c.Query("limit"), 10, 64)
	if limit < limitMin || limit > limitMax {
		limit = limitMin
	}
	urlValues.Set("limit", strconv.FormatInt(limit, 10))
	options = append(options, productCategoryModel.WithLimit(limit))
	page, _ := strconv.ParseInt(c.Query("page"), 10, 64)
	page = max(page, 0)
	options = append(options, productCategoryModel.WithPage(page), productCategoryModel.WithUrlValues(urlValues))
	return productCategoryModel.NewFilter(options...), nil
}

func ValidateProductCategory(ctx context.Context, c fiber.Ctx) (*productCategoryModel.ProductCategory, int, error) {
	ctxt := "ProductCategorySanitizer-ValidateProductCategory"
	var response productCategoryModel.ProductCategory
	err := c.Bind().Body(&response)
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBody")
		return nil, fiberErr.Code, err
	}
	if err = (&response).Validate(); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidate")
		return nil, fiber.StatusBadRequest, err
	}
	return &response, fiber.StatusOK, nil
}
