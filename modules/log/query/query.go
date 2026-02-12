package query

import (
	"context"

	"github.com/jackc/pgx/v5"
	logModel "github.com/roysitumorang/sadia/modules/log/model"
)

type (
	LogQuery interface {
		FindLogs(ctx context.Context, filter *logModel.Filter) ([]*logModel.Log, int64, int64, error)
		CreateLog(ctx context.Context, tx pgx.Tx, request *logModel.Log) (*logModel.Log, error)
	}
)
