package usecase

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	jwtModel "github.com/roysitumorang/sadia/modules/jwt/model"
	jwtQuery "github.com/roysitumorang/sadia/modules/jwt/query"
	"go.uber.org/zap"
)

type (
	jwtUseCase struct {
		jwtQuery jwtQuery.JwtQuery
	}
)

func New(
	jwtQuery jwtQuery.JwtQuery,
) JwtUseCase {
	return &jwtUseCase{
		jwtQuery: jwtQuery,
	}
}

func (q *jwtUseCase) CreateJWT(ctx context.Context, tx pgx.Tx, accountID string) (*jwtModel.JsonWebToken, error) {
	ctxt := "JwtUseCase-CreateJWT"
	response, err := q.jwtQuery.CreateJWT(ctx, tx, accountID)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJwt")
	}
	return response, err
}

func (q *jwtUseCase) DeleteJWTs(ctx context.Context, tx pgx.Tx, filter *jwtModel.DeleteFilter) (int64, error) {
	ctxt := "JwtUseCase-DeleteJWTs"
	rowsAffected, err := q.jwtQuery.DeleteJWTs(ctx, tx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
	}
	return rowsAffected, err
}

func (q *jwtUseCase) FindJWTs(ctx context.Context, filter *jwtModel.Filter) ([]*jwtModel.JsonWebToken, *models.Pagination, error) {
	ctxt := "JwtUseCase-FindJWTs"
	jsonWebTokens, total, pages, err := q.jwtQuery.FindJWTs(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindJWTs")
		return nil, nil, err
	}
	n := len(jsonWebTokens)
	rows := make([]*jwtModel.JsonWebToken, n)
	if n > 0 {
		copy(rows, jsonWebTokens)
	}
	pagination, err := helper.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *jwtUseCase) ConsumeMessage(ctx context.Context, topic string, message []byte) error {
	if topic != models.TopicJwt {
		return nil
	}
	return nil
}
