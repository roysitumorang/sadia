package sanitizer

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
	productModel "github.com/roysitumorang/sadia/modules/product/model"
	"go.uber.org/zap"
)

func FindProducts(ctx context.Context, c fiber.Ctx) (*productModel.Filter, error) {
	ctxt := "ProductSanitizer-FindProducts"
	originalURL, err := url.ParseRequestURI(helper.ByteSlice2String(c.Request().URI().FullURI()))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseRequestURI")
		return nil, err
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(originalURL.Path)
	urlValues := originalURL.Query()
	var options []productModel.FilterOption
	options = append(options, productModel.WithPaginationURL(builder.String()))
	if keyword := strings.TrimSpace(c.Query("q")); keyword != "" {
		urlValues.Set("q", keyword)
		options = append(options, productModel.WithKeyword(keyword))
	}
	limit, _ := utils.ParseInt(c.Query("limit"))
	if _, ok := models.MapLimits[limit]; !ok {
		limit = models.Limits[0]
	}
	urlValues.Set("limit", strconv.FormatInt(limit, 10))
	options = append(options, productModel.WithLimit(limit))
	page, _ := utils.ParseInt(c.Query("page"))
	page = max(page, 0)
	options = append(options, productModel.WithPage(page), productModel.WithUrlValues(urlValues))
	return productModel.NewFilter(options...), nil
}

func ValidateProduct(ctx context.Context, c fiber.Ctx) (*productModel.Product, int, error) {
	ctxt := "ProductSanitizer-ValidateProduct"
	response := new(productModel.Product)
	response.ID = c.Params("id")
	err := c.Bind().Body(response)
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
