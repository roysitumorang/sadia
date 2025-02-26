package sanitizer

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	"go.uber.org/zap"
)

func FindAccounts(ctx context.Context, c *fiber.Ctx) (*accountModel.Filter, error) {
	ctxt := "AccountSanitizer-FindAccounts"
	originalURL, err := url.ParseRequestURI(c.OriginalURL())
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseRequestURI")
		return nil, err
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(originalURL.Path)
	urlValues := originalURL.Query()
	var options []accountModel.FilterOption
	options = append(options, accountModel.WithPaginationURL(builder.String()))
	if keyword := strings.TrimSpace(c.Query("q")); keyword != "" {
		urlValues.Set("q", keyword)
		options = append(options, accountModel.WithKeyword(keyword))
	}
	if rawStatusList, ok := urlValues["status"]; ok {
		mapStatus := map[string]int{}
		var statusList []int
		for _, rawStatus := range rawStatusList {
			rawStatus = strings.TrimSpace(rawStatus)
			if _, ok := mapStatus[rawStatus]; rawStatus == "" || ok {
				continue
			}
			status, err := strconv.Atoi(rawStatus)
			if err != nil {
				continue
			}
			statusList = append(statusList, status)
			mapStatus[rawStatus] = 1
		}
		options = append(options, accountModel.WithStatusList(statusList...))
	}
	if limit, _ := strconv.ParseInt(c.Query("limit"), 10, 64); limit > 0 {
		urlValues.Set("limit", c.Query("limit"))
		options = append(options, accountModel.WithLimit(limit))
	}
	page, _ := strconv.ParseInt(c.Query("page"), 10, 64)
	page = max(page, 1)
	options = append(options, accountModel.WithPage(page), accountModel.WithUrlValues(urlValues))
	return accountModel.NewFilter(options...), nil
}

func ValidateAccount(ctx context.Context, c *fiber.Ctx) (*models.NewAccount, int, error) {
	ctxt := "AccountSanitizer-ValidateAccount"
	var response models.NewAccount
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

func ValidateAdmin(ctx context.Context, c *fiber.Ctx) (*accountModel.NewAdmin, int, error) {
	ctxt := "AccountSanitizer-ValidateAdmin"
	var response accountModel.NewAdmin
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

func ValidateUser(ctx context.Context, c *fiber.Ctx) (*accountModel.NewUser, int, error) {
	ctxt := "AccountSanitizer-ValidateUser"
	var response accountModel.NewUser
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

func ValidateDeactivation(ctx context.Context, c *fiber.Ctx) (*accountModel.Deactivation, int, error) {
	ctxt := "AccountSanitizer-ValidateDeactivation"
	var response accountModel.Deactivation
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

func ValidateLogin(ctx context.Context, c *fiber.Ctx) (*accountModel.LoginRequest, int, error) {
	ctxt := "AccountSanitizer-ValidateLogin"
	var response accountModel.LoginRequest
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

func ValidateConfirmation(ctx context.Context, c *fiber.Ctx) (*accountModel.Confirmation, int, error) {
	ctxt := "AccountSanitizer-ValidateConfirmation"
	var response accountModel.Confirmation
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

func ValidateForgotPassword(ctx context.Context, c *fiber.Ctx) (*accountModel.ForgotPassword, int, error) {
	ctxt := "AccountSanitizer-ValidateForgotPassword"
	var response accountModel.ForgotPassword
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

func ValidateResetPassword(ctx context.Context, c *fiber.Ctx) (*accountModel.ResetPassword, int, error) {
	ctxt := "AccountSanitizer-ValidateResetPassword"
	var response accountModel.ResetPassword
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

func ValidateChangePassword(ctx context.Context, c *fiber.Ctx) (*accountModel.ChangePassword, int, error) {
	ctxt := "AccountSanitizer-ValidateChangePassword"
	var response accountModel.ChangePassword
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

func ValidateChangeUsername(ctx context.Context, c *fiber.Ctx) (*accountModel.ChangeUsername, int, error) {
	ctxt := "AccountSanitizer-ValidateChangeUsername"
	var response accountModel.ChangeUsername
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

func ValidateChangeEmail(ctx context.Context, c *fiber.Ctx) (*accountModel.ChangeEmail, int, error) {
	ctxt := "AccountSanitizer-ValidateChangeEmail"
	var response accountModel.ChangeEmail
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

func ValidateChangePhone(ctx context.Context, c *fiber.Ctx) (*accountModel.ChangePhone, int, error) {
	ctxt := "AccountSanitizer-ValidateChangePhone"
	var response accountModel.ChangePhone
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

func FindAdmins(ctx context.Context, c *fiber.Ctx) (*accountModel.Filter, error) {
	ctxt := "AccountSanitizer-FindAdmins"
	originalURL, err := url.ParseRequestURI(c.OriginalURL())
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseRequestURI")
		return nil, err
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(originalURL.Path)
	urlValues := originalURL.Query()
	var options []accountModel.FilterOption
	options = append(options, accountModel.WithPaginationURL(builder.String()))
	if keyword := strings.TrimSpace(c.Query("q")); keyword != "" {
		urlValues.Set("q", keyword)
		options = append(options, accountModel.WithKeyword(keyword))
	}
	if rawStatusList, ok := urlValues["status"]; ok {
		mapStatus := map[string]int{}
		var statusList []int
		for _, rawStatus := range rawStatusList {
			rawStatus = strings.TrimSpace(rawStatus)
			if _, ok := mapStatus[rawStatus]; rawStatus == "" || ok {
				continue
			}
			status, err := strconv.Atoi(rawStatus)
			if err != nil {
				continue
			}
			statusList = append(statusList, status)
			mapStatus[rawStatus] = 1
		}
		options = append(options, accountModel.WithStatusList(statusList...))
	}
	if limit, _ := strconv.ParseInt(c.Query("limit"), 10, 64); limit > 0 {
		urlValues.Set("limit", c.Query("limit"))
		options = append(options, accountModel.WithLimit(limit))
	}
	page, _ := strconv.ParseInt(c.Query("page"), 10, 64)
	page = max(page, 1)
	options = append(options, accountModel.WithPage(page), accountModel.WithUrlValues(urlValues))
	return accountModel.NewFilter(options...), nil
}

func FindUsers(ctx context.Context, c *fiber.Ctx) (*accountModel.Filter, error) {
	ctxt := "AccountSanitizer-FindUsers"
	originalURL, err := url.ParseRequestURI(c.OriginalURL())
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseRequestURI")
		return nil, err
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(originalURL.Path)
	urlValues := originalURL.Query()
	var options []accountModel.FilterOption
	options = append(options, accountModel.WithPaginationURL(builder.String()))
	if keyword := strings.TrimSpace(c.Query("q")); keyword != "" {
		urlValues.Set("q", keyword)
		options = append(options, accountModel.WithKeyword(keyword))
	}
	if rawStatusList, ok := urlValues["status"]; ok {
		mapStatus := map[string]int{}
		var statusList []int
		for _, rawStatus := range rawStatusList {
			rawStatus = strings.TrimSpace(rawStatus)
			if _, ok := mapStatus[rawStatus]; rawStatus == "" || ok {
				continue
			}
			status, err := strconv.Atoi(rawStatus)
			if err != nil {
				continue
			}
			statusList = append(statusList, status)
			mapStatus[rawStatus] = 1
		}
		options = append(options, accountModel.WithStatusList(statusList...))
	}
	if limit, _ := strconv.ParseInt(c.Query("limit"), 10, 64); limit > 0 {
		urlValues.Set("limit", c.Query("limit"))
		options = append(options, accountModel.WithLimit(limit))
	}
	page, _ := strconv.ParseInt(c.Query("page"), 10, 64)
	page = max(page, 1)
	options = append(options, accountModel.WithPage(page), accountModel.WithUrlValues(urlValues))
	return accountModel.NewFilter(options...), nil
}
