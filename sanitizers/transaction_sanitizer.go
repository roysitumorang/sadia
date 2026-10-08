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

func FindTransactions(ctx context.Context, c fiber.Ctx) (*models.TransactionFilter, error) {
	ctxt := "TransactionSanitizer-FindTransactions"
	originalURL, err := url.ParseRequestURI(helper.ByteSlice2String(c.Request().URI().FullURI()))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseRequestURI")
		return nil, err
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(originalURL.Path)
	urlValues := originalURL.Query()
	var options []models.TransactionFilterOption
	options = append(options, models.TransactionWithPaginationURL(builder.String()))
	if keyword := strings.TrimSpace(c.Query("q")); keyword != "" {
		urlValues.Set("q", keyword)
		options = append(options, models.TransactionWithKeyword(keyword))
	}
	limit, _ := utils.ParseInt(c.Query("limit"))
	if _, ok := models.MapLimits[limit]; !ok {
		limit = models.Limits[0]
	}
	urlValues.Set("limit", strconv.FormatInt(limit, 10))
	page, _ := utils.ParseInt(c.Query("page"))
	page = max(page, 0)
	options = append(options, models.TransactionWithPage(page), models.TransactionWithUrlValues(urlValues))
	return models.NewTransactionFilter(options...), nil
}

func ValidateTransaction(ctx context.Context, c fiber.Ctx) (*models.Transaction, int, error) {
	ctxt := "TransactionSanitizer-ValidateTransaction"
	response := new(models.Transaction)
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

func ValidateCart(ctx context.Context, c fiber.Ctx) (*models.Transaction, int, error) {
	ctxt := "TransactionSanitizer-ValidateCart"
	response := new(models.Transaction)
	form, err := url.ParseQuery(helper.ByteSlice2String(c.Body()))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseQuery")
		return response, fiber.StatusBadRequest, err
	}
	if discounts := form["discount"]; len(discounts) > 0 {
		discount, err := strconv.ParseUint(discounts[0], 10, 64)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
			return response, fiber.StatusBadRequest, err
		}
		response.Discount = discount
	}
	productIDs := form["line_items[][product_id]"]
	quantities := form["line_items[][quantity]"]
	for i, rawProductID := range productIDs {
		lineItem := new(models.LineItem)
		productID, err := strconv.ParseUint(rawProductID, 10, 64)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
			return response, fiber.StatusBadRequest, err
		}
		lineItem.ProductID = productID
		quantity, err := strconv.ParseUint(quantities[i], 10, 64)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseUint")
			return response, fiber.StatusBadRequest, err
		}
		lineItem.Quantity = quantity
		response.LineItems = append(response.LineItems, lineItem)
	}
	return response, fiber.StatusOK, nil
}

func ValidateLineItem(ctx context.Context, c fiber.Ctx) (*models.LineItem, int, error) {
	ctxt := "TransactionSanitizer-ValidateLineItem"
	response := new(models.LineItem)
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
