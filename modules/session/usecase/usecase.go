package usecase

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/models"
	sessionModel "github.com/roysitumorang/sadia/modules/session/model"
)

type (
	SessionUseCase interface {
		FindSessions(ctx context.Context, filter *sessionModel.Filter) ([]*sessionModel.Session, *models.Pagination, error)
		CreateSession(ctx context.Context, tx pgx.Tx, request *sessionModel.Session) (*sessionModel.Session, error)
		UpdateSession(ctx context.Context, tx pgx.Tx, request *sessionModel.Session) error
		CreateSpending(ctx context.Context, tx pgx.Tx, request *sessionModel.Spending) error
		ConsumeMessage(ctx context.Context, topic string, message []byte) error
	}
)
