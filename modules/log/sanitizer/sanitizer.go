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
	logModel "github.com/roysitumorang/sadia/modules/log/model"
	"go.uber.org/zap"
)

func FindLogs(ctx context.Context, c fiber.Ctx) (*logModel.Filter, error) {
	ctxt := "LogSanitizer-FindLogs"
	originalURL, err := url.ParseRequestURI(helper.ByteSlice2String(c.Request().URI().FullURI()))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrParseRequestURI")
		return nil, err
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(originalURL.Path)
	urlValues := originalURL.Query()
	var options []logModel.FilterOption
	options = append(options, logModel.WithPaginationURL(builder.String()))
	limit, _ := utils.ParseInt(c.Query("limit"))
	if _, ok := models.MapLimits[limit]; !ok {
		limit = models.Limits[0]
	}
	urlValues.Set("limit", strconv.FormatInt(limit, 10))
	options = append(options, logModel.WithLimit(limit))
	page, _ := utils.ParseInt(c.Query("page"))
	page = max(page, 0)
	options = append(options, logModel.WithPage(page), logModel.WithUrlValues(urlValues))
	return logModel.NewFilter(options...), nil
}
