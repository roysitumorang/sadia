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
	sessionModel "github.com/roysitumorang/sadia/modules/session/model"
	"go.uber.org/zap"
)

func FindSessions(ctx context.Context, c fiber.Ctx) (*sessionModel.Filter, error) {
	ctxt := "SessionSanitizer-FindSessions"
	originalURL, err := url.ParseRequestURI(helper.ByteSlice2String(c.Request().URI().FullURI()))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseRequestURI")
		return nil, err
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(originalURL.Path)
	urlValues := originalURL.Query()
	var options []sessionModel.FilterOption
	options = append(options, sessionModel.WithPaginationURL(builder.String()))
	if keyword := strings.TrimSpace(c.Query("q")); keyword != "" {
		urlValues.Set("q", keyword)
		options = append(options, sessionModel.WithKeyword(keyword))
	}
	limit, _ := utils.ParseInt(c.Query("limit"))
	if _, ok := models.MapLimits[limit]; !ok {
		limit = models.Limits[0]
	}
	urlValues.Set("limit", strconv.FormatInt(limit, 10))
	options = append(options, sessionModel.WithLimit(limit))
	page, _ := utils.ParseInt(c.Query("page"))
	page = max(page, 0)
	options = append(options, sessionModel.WithPage(page), sessionModel.WithUrlValues(urlValues))
	return sessionModel.NewFilter(options...), nil
}

func ValidateSession(ctx context.Context, c fiber.Ctx) (*sessionModel.Session, int, error) {
	ctxt := "SessionSanitizer-ValidateSession"
	response := new(sessionModel.Session)
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

func ValidateSpending(ctx context.Context, c fiber.Ctx) (*sessionModel.Spending, int, error) {
	ctxt := "SessionSanitizer-ValidateSpending"
	response := new(sessionModel.Spending)
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
