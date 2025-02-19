package usecase

import (
	"context"
	"net/url"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/models"
	jwtModel "github.com/roysitumorang/sadia/modules/jwt/model"
)

type (
	JwtUseCase interface {
		CreateJWT(ctx context.Context, tx pgx.Tx, request jwtModel.JsonWebToken) error
		DeleteExpiredJWTs(ctx context.Context) (int64, error)
		FindJWTs(ctx context.Context, filter *jwtModel.Filter, urlValues url.Values) ([]*jwtModel.JsonWebToken, *models.Pagination, error)
	}
)
