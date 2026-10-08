package services

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/repositories"
	"go.uber.org/zap"
)

type SessionService interface {
	FindSessions(ctx context.Context, filter *models.SessionFilter) ([]*models.Session, *models.Pagination, error)
	CreateSession(ctx context.Context, tx pgx.Tx, request *models.Session) (*models.Session, error)
	UpdateSession(ctx context.Context, tx pgx.Tx, request *models.Session) error
	CreateSpending(ctx context.Context, tx pgx.Tx, request *models.Spending) error
	ConsumeMessage(ctx context.Context, topic string, message []byte) error
}

type sessionService struct {
	sessionRepository repositories.SessionRepository
}

func NewSessionService(
	sessionRepository repositories.SessionRepository,
) SessionService {
	return &sessionService{
		sessionRepository: sessionRepository,
	}
}

func (q *sessionService) FindSessions(ctx context.Context, filter *models.SessionFilter) ([]*models.Session, *models.Pagination, error) {
	ctxt := "SessionService-FindSessions"
	sessionCategories, total, pages, err := q.sessionRepository.FindSessions(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindSessions")
		return nil, nil, err
	}
	n := len(sessionCategories)
	rows := make([]*models.Session, n)
	if n > 0 {
		copy(rows, sessionCategories)
	}
	pagination, err := models.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *sessionService) CreateSession(ctx context.Context, tx pgx.Tx, request *models.Session) (*models.Session, error) {
	ctxt := "SessionService-CreateSession"
	response, err := q.sessionRepository.CreateSession(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateSession")
	}
	return response, err
}

func (q *sessionService) UpdateSession(ctx context.Context, tx pgx.Tx, request *models.Session) error {
	ctxt := "SessionService-UpdateSession"
	err := q.sessionRepository.UpdateSession(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateSession")
	}
	return err
}

func (q *sessionService) CreateSpending(ctx context.Context, tx pgx.Tx, request *models.Spending) error {
	ctxt := "SessionService-CreateSpending"
	err := q.sessionRepository.CreateSpending(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateSpending")
	}
	return err
}

func (q *sessionService) ConsumeMessage(ctx context.Context, topic string, message []byte) error {
	if topic != models.TopicSession {
		return nil
	}
	return nil
}
