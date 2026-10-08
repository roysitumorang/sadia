package sanitizers

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/utils/v2"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	"go.uber.org/zap"
)

func FindProductCategories(ctx context.Context, c fiber.Ctx) (*models.ProductCategoryFilter, error) {
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
	var options []models.ProductCategoryFilterOption
	options = append(options, models.ProductCategoryWithPaginationURL(builder.String()))
	if keyword := strings.TrimSpace(c.Query("q")); keyword != "" {
		urlValues.Set("q", keyword)
		options = append(options, models.ProductCategoryWithKeyword(keyword))
	}
	limit, _ := utils.ParseInt(c.Query("limit"))
	if _, ok := models.MapLimits[limit]; !ok {
		limit = models.Limits[0]
	}
	urlValues.Set("limit", strconv.FormatInt(limit, 10))
	options = append(options, models.ProductCategoryWithLimit(limit))
	page, _ := utils.ParseInt(c.Query("page"))
	page = max(page, 0)
	options = append(options, models.ProductCategoryWithPage(page), models.ProductCategoryWithUrlValues(urlValues))
	return models.NewProductCategoryFilter(options...), nil
}

func ValidateProductCategory(ctx context.Context, c fiber.Ctx) (*models.ProductCategory, int, error) {
	ctxt := "ProductCategorySanitizer-ValidateProductCategory"
	response := &models.ProductCategory{}
	productCategoryID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
		return response, fiber.StatusNotFound, errors.New("category not found")
	}
	response.ID = productCategoryID
	err = c.Bind().Body(response)
	if fiberErr, ok := errors.AsType[*fiber.Error](err); ok {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBody")
		return response, fiberErr.Code, err
	}
	if err = response.Validate(); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidate")
		return response, fiber.StatusBadRequest, err
	}
	return response, fiber.StatusOK, nil
}
