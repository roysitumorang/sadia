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
	transactionModel "github.com/roysitumorang/sadia/modules/transaction/model"
	"go.uber.org/zap"
)

func FindTransactions(ctx context.Context, c fiber.Ctx) (*transactionModel.Filter, error) {
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
	var options []transactionModel.FilterOption
	options = append(options, transactionModel.WithPaginationURL(builder.String()))
	if keyword := strings.TrimSpace(c.Query("q")); keyword != "" {
		urlValues.Set("q", keyword)
		options = append(options, transactionModel.WithKeyword(keyword))
	}
	limit, _ := utils.ParseInt(c.Query("limit"))
	if _, ok := models.MapLimits[limit]; !ok {
		limit = models.Limits[0]
	}
	urlValues.Set("limit", strconv.FormatInt(limit, 10))
	page, _ := utils.ParseInt(c.Query("page"))
	page = max(page, 0)
	options = append(options, transactionModel.WithPage(page), transactionModel.WithUrlValues(urlValues))
	return transactionModel.NewFilter(options...), nil
}

func ValidateTransaction(ctx context.Context, c fiber.Ctx) (*transactionModel.Transaction, int, error) {
	ctxt := "TransactionSanitizer-ValidateTransaction"
	response := new(transactionModel.Transaction)
	err := c.Bind().Body(response)
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBody")
		return response, fiberErr.Code, err
	}
	if err = response.Validate(); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidate")
		return response, fiber.StatusBadRequest, err
	}
	return response, fiber.StatusOK, nil
}

func ValidateCart(ctx context.Context, c fiber.Ctx) (*transactionModel.Transaction, int, error) {
	ctxt := "TransactionSanitizer-ValidateCart"
	response := new(transactionModel.Transaction)
	form, err := url.ParseQuery(helper.ByteSlice2String(c.Body()))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseQuery")
		return response, fiber.StatusBadRequest, err
	}
	if discounts := form["discount"]; len(discounts) > 0 {
		discount, err := utils.ParseInt(discounts[0])
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseInt")
			return response, fiber.StatusBadRequest, err
		}
		response.Discount = discount
	}
	productIDs := form["line_items[][product_id]"]
	quantities := form["line_items[][quantity]"]
	for i, rawProductID := range productIDs {
		lineItem := new(transactionModel.LineItem)
		productID, err := utils.ParseInt(rawProductID)
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseInt")
			return response, fiber.StatusBadRequest, err
		}
		lineItem.ProductID = productID
		quantity, err := utils.ParseInt(quantities[i])
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseInt")
			return response, fiber.StatusBadRequest, err
		}
		lineItem.Quantity = quantity
		response.LineItems = append(response.LineItems, lineItem)
	}
	return response, fiber.StatusOK, nil
}

func ValidateLineItem(ctx context.Context, c fiber.Ctx) (*transactionModel.LineItem, int, error) {
	ctxt := "TransactionSanitizer-ValidateLineItem"
	response := new(transactionModel.LineItem)
	err := c.Bind().Body(response)
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBody")
		return response, fiberErr.Code, err
	}
	if err = response.Validate(); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidate")
		return response, fiber.StatusBadRequest, err
	}
	return response, fiber.StatusOK, nil
}
