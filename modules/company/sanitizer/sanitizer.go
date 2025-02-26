package sanitizer

import (
	"context"
	"errors"
	"math"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/roysitumorang/sadia/helper"
	companyModel "github.com/roysitumorang/sadia/modules/company/model"
	"go.uber.org/zap"
)

func FindCompanies(ctx context.Context, c *fiber.Ctx) (*companyModel.Filter, error) {
	ctxt := "CompanySanitizer-FindCompanies"
	originalURL, err := url.ParseRequestURI(c.OriginalURL())
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseRequestURI")
		return nil, err
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(originalURL.Path)
	urlValues := originalURL.Query()
	var options []companyModel.FilterOption
	options = append(options, companyModel.WithPaginationURL(builder.String()))
	if keyword := strings.TrimSpace(c.Query("q")); keyword != "" {
		urlValues.Set("q", keyword)
		options = append(options, companyModel.WithKeyword(keyword))
	}
	if rawStatusList, ok := urlValues["status"]; ok {
		mapStatus := map[string]int{}
		var statusList []int8
		for _, rawStatus := range rawStatusList {
			rawStatus = strings.TrimSpace(rawStatus)
			if _, ok := mapStatus[rawStatus]; rawStatus == "" || ok {
				continue
			}
			status, err := strconv.Atoi(rawStatus)
			if err != nil || status < math.MinInt8 || status > math.MaxInt8 {
				continue
			}
			statusList = append(statusList, int8(status))
			mapStatus[rawStatus] = 1
		}
		options = append(options, companyModel.WithStatusList(statusList...))
	}
	if limit, _ := strconv.ParseInt(c.Query("limit"), 10, 64); limit > 0 {
		urlValues.Set("limit", c.Query("limit"))
		options = append(options, companyModel.WithLimit(limit))
	}
	page, _ := strconv.ParseInt(c.Query("page"), 10, 64)
	page = max(page, 1)
	options = append(options, companyModel.WithPage(page), companyModel.WithUrlValues(urlValues))
	return companyModel.NewFilter(options...), nil
}

func ValidateCompany(ctx context.Context, c *fiber.Ctx) (*companyModel.NewCompany, int, error) {
	ctxt := "CompanySanitizer-ValidateCompany"
	var response companyModel.NewCompany
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

func ValidateDeactivation(ctx context.Context, c *fiber.Ctx) (*companyModel.Deactivation, int, error) {
	ctxt := "CompanySanitizer-ValidateDeactivation"
	var response companyModel.Deactivation
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

func ValidateUpdateCompany(ctx context.Context, c *fiber.Ctx) (*companyModel.UpdateCompany, int, error) {
	ctxt := "CompanySanitizer-ValidateUpdateCompany"
	var response companyModel.UpdateCompany
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
