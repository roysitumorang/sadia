package usecase

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/models"
	logModel "github.com/roysitumorang/sadia/modules/log/model"
)

type (
	LogUseCase interface {
		FindLogs(ctx context.Context, filter *logModel.Filter) ([]*logModel.Log, *models.Pagination, error)
		CreateLog(ctx context.Context, tx pgx.Tx, request *logModel.Log) (*logModel.Log, error)
	}
)
