package sanitizer

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/roysitumorang/sadia/helper"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	"go.uber.org/zap"
)

var (
	phoneNumberRegex = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
)

func FindAccounts(ctx context.Context, c *fiber.Ctx) (*accountModel.Filter, url.Values, error) {
	ctxt := "AccountSanitizer-FindAccounts"
	originalURL, err := url.ParseRequestURI(c.OriginalURL())
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseRequestURI")
		return nil, nil, err
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(originalURL.Path)
	urlValues := url.Values{}
	var options []accountModel.FilterOption
	options = append(options, accountModel.WithPaginationURL(builder.String()))
	if keyword := strings.TrimSpace(c.Query("q")); keyword != "" {
		urlValues.Set("q", keyword)
		options = append(options, accountModel.WithKeyword(keyword))
	}
	if limit, _ := strconv.ParseInt(c.Query("limit"), 10, 64); limit > 0 {
		urlValues.Set("limit", c.Query("limit"))
		options = append(options, accountModel.WithLimit(limit))
	}
	page, _ := strconv.ParseInt(c.Query("page"), 10, 64)
	page = max(page, 1)
	options = append(options, accountModel.WithPage(page))
	return accountModel.NewFilter(options...), urlValues, nil
}

func ValidateAccount(ctx context.Context, c *fiber.Ctx) (*accountModel.NewAccount, int, error) {
	ctxt := "AccountSanitizer-ValidateAccount"
	var response accountModel.NewAccount
	err := c.BodyParser(&response)
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBodyParser")
		return nil, fiberErr.Code, err
	}
	if response.AccountType != accountModel.AccountTypeAdmin &&
		response.AccountType != accountModel.AccountTypeUser {
		return nil,
			fiber.StatusBadRequest,
			fmt.Errorf(
				"account_type: should be either %d or %d",
				accountModel.AccountTypeAdmin,
				accountModel.AccountTypeUser,
			)
	}
	if response.Name = strings.TrimSpace(response.Name); response.Name == "" {
		return nil, fiber.StatusBadRequest, errors.New("name: is required")
	}
	if response.Username = strings.TrimSpace(response.Username); response.Username == "" {
		return nil, fiber.StatusBadRequest, errors.New("username: is required")
	}
	if response.Email != nil {
		if *response.Email != "" {
			if _, err = mail.ParseAddress(*response.Email); err != nil {
				return nil, fiber.StatusBadRequest, errors.New("email: invalid address")
			}
		} else {
			response.Email = nil
		}
	}
	if response.Phone = strings.TrimSpace(response.Phone); response.Phone == "" {
		return nil, fiber.StatusBadRequest, errors.New("phone: is required")
	}
	if phoneNumberRegex.Find(helper.String2ByteSlice(response.Phone)) == nil {
		return nil, fiber.StatusBadRequest, errors.New("phone: invalid number")
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
	if response.Reason = strings.TrimSpace(response.Reason); response.Reason == "" {
		return nil, fiber.StatusBadRequest, errors.New("reason: is required")
	}
	return &response, fiber.StatusOK, nil
}
