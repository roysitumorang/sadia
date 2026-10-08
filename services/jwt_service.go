package services

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/repositories"
	"go.uber.org/zap"
)

type JwtService interface {
	CreateJWT(ctx context.Context, tx pgx.Tx, accountID uint64) (*models.JsonWebToken, error)
	DeleteJWTs(ctx context.Context, tx pgx.Tx, filter *models.JwtDeleteFilter) (int64, error)
	FindJWTs(ctx context.Context, filter *models.JwtFilter) ([]*models.JsonWebToken, *models.Pagination, error)
	ConsumeMessage(ctx context.Context, topic string, message []byte) error
}

type jwtService struct {
	jwtRepository repositories.JwtRepository
}

func NewJwtService(
	jwtRepository repositories.JwtRepository,
) JwtService {
	return &jwtService{
		jwtRepository: jwtRepository,
	}
}

func (q *jwtService) CreateJWT(ctx context.Context, tx pgx.Tx, accountID uint64) (*models.JsonWebToken, error) {
	ctxt := "JwtService-CreateJWT"
	response, err := q.jwtRepository.CreateJWT(ctx, tx, accountID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJwt")
	}
	return response, err
}

func (q *jwtService) DeleteJWTs(ctx context.Context, tx pgx.Tx, filter *models.JwtDeleteFilter) (int64, error) {
	ctxt := "JwtService-DeleteJWTs"
	rowsAffected, err := q.jwtRepository.DeleteJWTs(ctx, tx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
	}
	return rowsAffected, err
}

func (q *jwtService) FindJWTs(ctx context.Context, filter *models.JwtFilter) ([]*models.JsonWebToken, *models.Pagination, error) {
	ctxt := "JwtService-FindJWTs"
	jsonWebTokens, total, pages, err := q.jwtRepository.FindJWTs(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindJWTs")
		return nil, nil, err
	}
	n := len(jsonWebTokens)
	rows := make([]*models.JsonWebToken, n)
	if n > 0 {
		copy(rows, jsonWebTokens)
	}
	pagination, err := models.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *jwtService) ConsumeMessage(ctx context.Context, topic string, message []byte) error {
	if topic != models.TopicJwt {
		return nil
	}
	return nil
}
