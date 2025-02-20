package sanitizer

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	jwtModel "github.com/roysitumorang/sadia/modules/jwt/model"
)

func FindJWTs(ctx context.Context, c *fiber.Ctx) (*jwtModel.Filter, url.Values, error) {
	originalURL, err := url.ParseRequestURI(c.OriginalURL())
	if err != nil {
		return nil, nil, err
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(originalURL.Path)
	urlValues := url.Values{}
	var options []jwtModel.FilterOption
	options = append(options, jwtModel.WithPaginationURL(builder.String()))
	if limit, _ := strconv.ParseInt(c.Query("limit"), 10, 64); limit > 0 {
		urlValues.Set("limit", c.Query("limit"))
		options = append(options, jwtModel.WithLimit(limit))
	}
	page, _ := strconv.ParseInt(c.Query("page"), 10, 64)
	page = max(page, 1)
	options = append(options, jwtModel.WithPage(page))
	return jwtModel.NewFilter(options...), urlValues, nil
}
