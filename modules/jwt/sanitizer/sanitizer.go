package sanitizer

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	jwtModel "github.com/roysitumorang/sadia/modules/jwt/model"
)

func FindJWTs(ctx context.Context, c *fiber.Ctx) (*jwtModel.Filter, error) {
	originalURL, err := url.ParseRequestURI(c.OriginalURL())
	if err != nil {
		return nil, err
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(originalURL.Path)
	urlValues := originalURL.Query()
	var options []jwtModel.FilterOption
	options = append(options, jwtModel.WithPaginationURL(builder.String()))
	if rawAccountIDs, ok := urlValues["account_id"]; ok && len(rawAccountIDs) > 0 {
		mapAccountIDs := map[string]int{}
		var accountIDs []string
		for _, accountID := range rawAccountIDs {
			accountID = strings.TrimSpace(accountID)
			if _, ok := mapAccountIDs[accountID]; accountID == "" || ok {
				continue
			}
			accountIDs = append(accountIDs, accountID)
			mapAccountIDs[accountID] = 1
		}
		options = append(options, jwtModel.WithAccountIDs(accountIDs...))
	}
	if limit, _ := strconv.ParseInt(c.Query("limit"), 10, 64); limit > 0 {
		urlValues.Set("limit", c.Query("limit"))
		options = append(options, jwtModel.WithLimit(limit))
	}
	page, _ := strconv.ParseInt(c.Query("page"), 10, 64)
	page = max(page, 1)
	options = append(options, jwtModel.WithPage(page), jwtModel.WithUrlValues(urlValues))
	return jwtModel.NewFilter(options...), nil
}
