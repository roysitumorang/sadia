package usecase

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	logModel "github.com/roysitumorang/sadia/modules/log/model"
	logQuery "github.com/roysitumorang/sadia/modules/log/query"
	"go.uber.org/zap"
)

type (
	logUseCase struct {
		logQuery logQuery.LogQuery
	}
)

func New(
	logQuery logQuery.LogQuery,
) LogUseCase {
	return &logUseCase{
		logQuery: logQuery,
	}
}

func (q *logUseCase) FindLogs(ctx context.Context, filter *logModel.Filter) ([]*logModel.Log, *models.Pagination, error) {
	ctxt := "LogUseCase-FindLogs"
	logs, total, pages, err := q.logQuery.FindLogs(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindLogs")
		return nil, nil, err
	}
	n := len(logs)
	rows := make([]*logModel.Log, n)
	if n > 0 {
		copy(rows, logs)
	}
	pagination, err := helper.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *logUseCase) CreateLog(ctx context.Context, tx pgx.Tx, request *logModel.Log) (*logModel.Log, error) {
	ctxt := "LogUseCase-CreateLog"
	response, err := q.logQuery.CreateLog(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateLog")
	}
	return response, err
}
