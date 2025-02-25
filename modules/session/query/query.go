package query

import (
	"context"

	"github.com/jackc/pgx/v5"
	sessionModel "github.com/roysitumorang/sadia/modules/session/model"
)

type (
	SessionQuery interface {
		FindSessions(ctx context.Context, filter *sessionModel.Filter) ([]*sessionModel.Session, int64, int64, error)
		CreateSession(ctx context.Context, tx pgx.Tx, request *sessionModel.NewSession) (*sessionModel.Session, error)
		UpdateSession(ctx context.Context, tx pgx.Tx, request *sessionModel.Session) error
	}
)
