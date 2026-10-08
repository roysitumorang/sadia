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

func FindCompanies(ctx context.Context, c fiber.Ctx) (*models.CompanyFilter, error) {
	ctxt := "CompanySanitizer-FindCompanies"
	originalURL, err := url.ParseRequestURI(helper.ByteSlice2String(c.Request().URI().FullURI()))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseRequestURI")
		return nil, err
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(originalURL.Path)
	urlValues := originalURL.Query()
	var options []models.CompanyFilterOption
	options = append(options, models.CompanyWithPaginationURL(builder.String()))
	if keyword := strings.TrimSpace(c.Query("q")); keyword != "" {
		urlValues.Set("q", keyword)
		options = append(options, models.CompanyWithKeyword(keyword))
	}
	if rawStatusList, ok := urlValues["status"]; ok {
		mapStatus := map[string]struct{}{}
		var statusList []uint8
		for _, rawStatus := range rawStatusList {
			rawStatus = strings.TrimSpace(rawStatus)
			if _, ok := mapStatus[rawStatus]; rawStatus == "" || ok {
				continue
			}
			status, err := strconv.ParseUint(rawStatus, 10, 8)
			if err != nil {
				continue
			}
			statusList = append(statusList, uint8(status))
			mapStatus[rawStatus] = struct{}{}
		}
		options = append(options, models.CompanyWithStatusList(statusList...))
	}
	limit, _ := utils.ParseInt(c.Query("limit"))
	if _, ok := models.MapLimits[limit]; !ok {
		limit = models.Limits[0]
	}
	urlValues.Set("limit", strconv.FormatInt(limit, 10))
	page, _ := utils.ParseInt(c.Query("page"))
	page = max(page, 0)
	options = append(options, models.CompanyWithPage(page), models.CompanyWithUrlValues(urlValues))
	return models.NewCompanyFilter(options...), nil
}

func ValidateCompany(ctx context.Context, c fiber.Ctx) (*models.NewCompany, int, error) {
	ctxt := "CompanySanitizer-ValidateCompany"
	var response models.NewCompany
	err := c.Bind().Body(&response)
	if fiberErr, ok := errors.AsType[*fiber.Error](err); ok {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBody")
		return nil, fiberErr.Code, err
	}
	if err = (&response).Validate(); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidate")
		return nil, fiber.StatusBadRequest, err
	}
	return &response, fiber.StatusOK, nil
}

func ValidateCompanyDeactivation(ctx context.Context, c fiber.Ctx) (*models.CompanyDeactivation, int, error) {
	ctxt := "CompanySanitizer-ValidateCompanyDeactivation"
	var response models.CompanyDeactivation
	err := c.Bind().Body(&response)
	if fiberErr, ok := errors.AsType[*fiber.Error](err); ok {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBody")
		return nil, fiberErr.Code, err
	}
	if err = (&response).Validate(); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidate")
		return nil, fiber.StatusBadRequest, err
	}
	return &response, fiber.StatusOK, nil
}

func ValidateUpdateCompany(ctx context.Context, c fiber.Ctx) (*models.UpdateCompany, int, error) {
	ctxt := "CompanySanitizer-ValidateUpdateCompany"
	var response models.UpdateCompany
	err := c.Bind().Body(&response)
	if fiberErr, ok := errors.AsType[*fiber.Error](err); ok {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBody")
		return nil, fiberErr.Code, err
	}
	if err = (&response).Validate(); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrValidate")
		return nil, fiber.StatusBadRequest, err
	}
	return &response, fiber.StatusOK, nil
}
