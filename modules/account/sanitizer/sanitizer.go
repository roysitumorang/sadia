package sanitizer

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
)

func FindAccounts(ctx context.Context, c *fiber.Ctx) (*accountModel.Filter, url.Values, error) {
	originalURL, err := url.ParseRequestURI(c.OriginalURL())
	if err != nil {
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
