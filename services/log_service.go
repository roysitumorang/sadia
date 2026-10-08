package services

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/repositories"
	"go.uber.org/zap"
)

type LogService interface {
	FindLogs(ctx context.Context, filter *models.LogFilter) ([]*models.Log, *models.Pagination, error)
	CreateLog(ctx context.Context, tx pgx.Tx, request *models.Log) (*models.Log, error)
}

type logService struct {
	logRepository repositories.LogRepository
}

func NewLogService(
	logRepository repositories.LogRepository,
) LogService {
	return &logService{
		logRepository: logRepository,
	}
}

func (q *logService) FindLogs(ctx context.Context, filter *models.LogFilter) ([]*models.Log, *models.Pagination, error) {
	ctxt := "LogService-FindLogs"
	logs, total, pages, err := q.logRepository.FindLogs(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindLogs")
		return nil, nil, err
	}
	n := len(logs)
	rows := make([]*models.Log, n)
	if n > 0 {
		copy(rows, logs)
	}
	pagination, err := models.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *logService) CreateLog(ctx context.Context, tx pgx.Tx, request *models.Log) (*models.Log, error) {
	ctxt := "LogService-CreateLog"
	response, err := q.logRepository.CreateLog(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateLog")
	}
	return response, err
}
