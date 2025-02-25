package sanitizer

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/roysitumorang/sadia/helper"
	transactionModel "github.com/roysitumorang/sadia/modules/transaction/model"
	"go.uber.org/zap"
)

func FindTransactions(ctx context.Context, c *fiber.Ctx) (*transactionModel.Filter, error) {
	ctxt := "TransactionSanitizer-FindTransactions"
	originalURL, err := url.ParseRequestURI(c.OriginalURL())
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
	if limit, _ := strconv.ParseInt(c.Query("limit"), 10, 64); limit > 0 {
		urlValues.Set("limit", c.Query("limit"))
		options = append(options, transactionModel.WithLimit(limit))
	}
	page, _ := strconv.ParseInt(c.Query("page"), 10, 64)
	page = max(page, 1)
	options = append(options, transactionModel.WithPage(page), transactionModel.WithUrlValues(urlValues))
	return transactionModel.NewFilter(options...), nil
}

func ValidateTransaction(ctx context.Context, c *fiber.Ctx) (*transactionModel.Transaction, int, error) {
	ctxt := "TransactionSanitizer-ValidateTransaction"
	var response transactionModel.Transaction
	err := c.BodyParser(&response)
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBodyParser")
		return nil, fiberErr.Code, err
	}
	if err = (&response).Validate(); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidate")
		return nil, fiber.StatusBadRequest, err
	}
	return &response, fiber.StatusOK, nil
}
