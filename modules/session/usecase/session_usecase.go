package usecase

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	sessionModel "github.com/roysitumorang/sadia/modules/session/model"
	sessionQuery "github.com/roysitumorang/sadia/modules/session/query"
	"go.uber.org/zap"
)

type (
	sessionUseCase struct {
		sessionQuery sessionQuery.SessionQuery
	}
)

func New(
	sessionQuery sessionQuery.SessionQuery,
) SessionUseCase {
	return &sessionUseCase{
		sessionQuery: sessionQuery,
	}
}

func (q *sessionUseCase) FindSessions(ctx context.Context, filter *sessionModel.Filter) ([]*sessionModel.Session, *models.Pagination, error) {
	ctxt := "SessionUseCase-FindSessions"
	sessionCategories, total, pages, err := q.sessionQuery.FindSessions(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindSessions")
		return nil, nil, err
	}
	n := len(sessionCategories)
	rows := make([]*sessionModel.Session, n)
	if n > 0 {
		copy(rows, sessionCategories)
	}
	pagination, err := helper.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *sessionUseCase) CreateSession(ctx context.Context, tx pgx.Tx, request *sessionModel.NewSession) (*sessionModel.Session, error) {
	ctxt := "SessionUseCase-CreateSession"
	response, err := q.sessionQuery.CreateSession(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateSession")
	}
	return response, err
}

func (q *sessionUseCase) UpdateSession(ctx context.Context, tx pgx.Tx, request *sessionModel.Session) error {
	ctxt := "SessionUseCase-UpdateSession"
	err := q.sessionQuery.UpdateSession(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateSession")
	}
	return err
}

func (q *sessionUseCase) ConsumeMessage(ctx context.Context, topic string, message []byte) error {
	if topic != models.TopicSession {
		return nil
	}
	return nil
}
