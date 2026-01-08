package sanitizer

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/utils/v2"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	jwtModel "github.com/roysitumorang/sadia/modules/jwt/model"
)

func FindJWTs(ctx context.Context, c fiber.Ctx) (*jwtModel.Filter, error) {
	originalURL, err := url.ParseRequestURI(helper.ByteSlice2String(c.Request().URI().FullURI()))
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
		mapAccountIDs := map[int64]int{}
		var (
			accountID  int64
			accountIDs []int64
		)
		for _, rawAccountID := range rawAccountIDs {
			accountID, _ = utils.ParseInt(rawAccountID)
			if _, ok := mapAccountIDs[accountID]; accountID == 0 || ok {
				continue
			}
			accountIDs = append(accountIDs, accountID)
			mapAccountIDs[accountID] = 1
		}
		options = append(options, jwtModel.WithAccountIDs(accountIDs...))
	}
	limit, _ := utils.ParseInt(c.Query("limit"))
	if _, ok := models.MapLimits[limit]; !ok {
		limit = models.Limits[0]
	}
	urlValues.Set("limit", strconv.FormatInt(limit, 10))
	page, _ := utils.ParseInt(c.Query("page"))
	page = max(page, 0)
	options = append(options, jwtModel.WithPage(page), jwtModel.WithUrlValues(urlValues))
	return jwtModel.NewFilter(options...), nil
}
