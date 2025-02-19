package usecase

import (
	"context"
	"net/url"

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

func (q *jwtUseCase) CreateJWT(ctx context.Context, tx pgx.Tx, request jwtModel.JsonWebToken) error {
	ctxt := "JwtUseCase-CreateJWT"
	err := q.jwtQuery.CreateJWT(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJwt")
	}
	return err
}

func (q *jwtUseCase) DeleteExpiredJWTs(ctx context.Context) (int64, error) {
	ctxt := "JwtUseCase-DeleteExpiredJWTs"
	rowsAffected, err := q.jwtQuery.DeleteExpiredJWTs(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteExpiredJWTs")
	}
	return rowsAffected, err
}

func (q *jwtUseCase) FindJWTs(ctx context.Context, filter *jwtModel.Filter, urlValues url.Values) ([]*jwtModel.JsonWebToken, *models.Pagination, error) {
	ctxt := "JwtUseCase-FindJWTs"
	rows, total, pages, err := q.jwtQuery.FindJWTs(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindJWTs")
		return nil, nil, err
	}
	pagination, err := helper.SetPagination(total, pages, filter.PerPage, filter.Page, filter.PaginationURL, urlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}
