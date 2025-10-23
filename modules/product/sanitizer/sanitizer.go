package sanitizer

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/roysitumorang/sadia/helper"
	productModel "github.com/roysitumorang/sadia/modules/product/model"
	"go.uber.org/zap"
)

func FindProducts(ctx context.Context, c fiber.Ctx) (*productModel.Filter, error) {
	ctxt := "ProductSanitizer-FindProducts"
	limitMin, limitMax := helper.GetPaginationLimit()
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
	limit, _ := strconv.ParseInt(c.Query("limit"), 10, 64)
	if limit < limitMin || limit > limitMax {
		limit = limitMin
	}
	urlValues.Set("limit", strconv.FormatInt(limit, 10))
	options = append(options, productModel.WithLimit(limit))
	page, _ := strconv.ParseInt(c.Query("page"), 10, 64)
	page = max(page, 0)
	options = append(options, productModel.WithPage(page), productModel.WithUrlValues(urlValues))
	return productModel.NewFilter(options...), nil
}

func ValidateProduct(ctx context.Context, c fiber.Ctx) (*productModel.Product, int, error) {
	ctxt := "ProductSanitizer-ValidateProduct"
	var response productModel.Product
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
