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

func FindAccounts(ctx context.Context, c fiber.Ctx) (*models.AccountFilter, error) {
	ctxt := "AccountSanitizer-FindAccounts"
	originalURL, err := url.ParseRequestURI(helper.ByteSlice2String(c.Request().URI().FullURI()))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseRequestURI")
		return nil, err
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(originalURL.Path)
	urlValues := originalURL.Query()
	var options []models.AccountFilterOption
	options = append(options, models.AccountWithPaginationURL(builder.String()))
	if keyword := strings.TrimSpace(c.Query("q")); keyword != "" {
		urlValues.Set("q", keyword)
		options = append(options, models.AccountWithKeyword(keyword))
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
		options = append(options, models.AccountWithStatusList(statusList...))
	}
	limit, _ := utils.ParseInt(c.Query("limit"))
	if _, ok := models.MapLimits[limit]; !ok {
		limit = models.Limits[0]
	}
	urlValues.Set("limit", strconv.FormatInt(limit, 10))
	page, _ := utils.ParseInt(c.Query("page"))
	page = max(page, 0)
	options = append(options, models.AccountWithPage(page), models.AccountWithUrlValues(urlValues))
	return models.NewAccountFilter(options...), nil
}

func ValidateAccount(ctx context.Context, c fiber.Ctx) (*models.NewAccount, int, error) {
	ctxt := "AccountSanitizer-ValidateAccount"
	var response models.NewAccount
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

func ValidateAdmin(ctx context.Context, c fiber.Ctx) (*models.NewAdmin, int, error) {
	ctxt := "AccountSanitizer-ValidateAdmin"
	var response models.NewAdmin
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

func ValidateUser(ctx context.Context, c fiber.Ctx) (*models.NewUser, int, error) {
	ctxt := "AccountSanitizer-ValidateUser"
	var response models.NewUser
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

func ValidateAccountDeactivation(ctx context.Context, c fiber.Ctx) (*models.AccountDeactivation, int, error) {
	ctxt := "AccountSanitizer-ValidateAccountDeactivation"
	var response models.AccountDeactivation
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

func ValidateLogin(ctx context.Context, c fiber.Ctx) (*models.LoginRequest, int, error) {
	ctxt := "AccountSanitizer-ValidateLogin"
	response := new(models.LoginRequest)
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

func ValidateConfirmation(ctx context.Context, c fiber.Ctx) (*models.Confirmation, int, error) {
	ctxt := "AccountSanitizer-ValidateConfirmation"
	var response models.Confirmation
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

func ValidateForgotPassword(ctx context.Context, c fiber.Ctx) (*models.ForgotPassword, int, error) {
	ctxt := "AccountSanitizer-ValidateForgotPassword"
	var response models.ForgotPassword
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

func ValidateResetPassword(ctx context.Context, c fiber.Ctx) (*models.ResetPassword, int, error) {
	ctxt := "AccountSanitizer-ValidateResetPassword"
	var response models.ResetPassword
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

func ValidateChangePassword(ctx context.Context, c fiber.Ctx) (*models.ChangePassword, int, error) {
	ctxt := "AccountSanitizer-ValidateChangePassword"
	var response models.ChangePassword
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

func ValidateChangeUsername(ctx context.Context, c fiber.Ctx) (*models.ChangeUsername, int, error) {
	ctxt := "AccountSanitizer-ValidateChangeUsername"
	var response models.ChangeUsername
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

func ValidateChangeEmail(ctx context.Context, c fiber.Ctx) (*models.ChangeEmail, int, error) {
	ctxt := "AccountSanitizer-ValidateChangeEmail"
	var response models.ChangeEmail
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

func ValidateChangePhone(ctx context.Context, c fiber.Ctx) (*models.ChangePhone, int, error) {
	ctxt := "AccountSanitizer-ValidateChangePhone"
	var response models.ChangePhone
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

func FindAdmins(ctx context.Context, c fiber.Ctx) (*models.AccountFilter, error) {
	ctxt := "AccountSanitizer-FindAdmins"
	originalURL, err := url.ParseRequestURI(helper.ByteSlice2String(c.Request().URI().FullURI()))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseRequestURI")
		return nil, err
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(originalURL.Path)
	urlValues := originalURL.Query()
	var options []models.AccountFilterOption
	options = append(options, models.AccountWithPaginationURL(builder.String()))
	if keyword := strings.TrimSpace(c.Query("q")); keyword != "" {
		urlValues.Set("q", keyword)
		options = append(options, models.AccountWithKeyword(keyword))
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
		options = append(options, models.AccountWithStatusList(statusList...))
	}
	if limit, _ := utils.ParseInt(c.Query("limit")); limit > 0 {
		urlValues.Set("limit", c.Query("limit"))
		options = append(options, models.AccountWithLimit(limit))
	}
	page, _ := utils.ParseInt(c.Query("page"))
	page = max(page, 1)
	options = append(options, models.AccountWithPage(page), models.AccountWithUrlValues(urlValues))
	return models.NewAccountFilter(options...), nil
}

func FindUsers(ctx context.Context, c fiber.Ctx) (*models.AccountFilter, error) {
	ctxt := "AccountSanitizer-FindUsers"
	originalURL, err := url.ParseRequestURI(helper.ByteSlice2String(c.Request().URI().FullURI()))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseRequestURI")
		return nil, err
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(originalURL.Path)
	urlValues := originalURL.Query()
	var options []models.AccountFilterOption
	options = append(options, models.AccountWithPaginationURL(builder.String()))
	if keyword := strings.TrimSpace(c.Query("q")); keyword != "" {
		urlValues.Set("q", keyword)
		options = append(options, models.AccountWithKeyword(keyword))
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
		options = append(options, models.AccountWithStatusList(statusList...))
	}
	if limit, _ := utils.ParseInt(c.Query("limit")); limit > 0 {
		urlValues.Set("limit", c.Query("limit"))
		options = append(options, models.AccountWithLimit(limit))
	}
	page, _ := utils.ParseInt(c.Query("page"))
	page = max(page, 1)
	options = append(options, models.AccountWithPage(page), models.AccountWithUrlValues(urlValues))
	return models.NewAccountFilter(options...), nil
}
