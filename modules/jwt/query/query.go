package query

import (
	"context"

	"github.com/jackc/pgx/v5"
	jwtModel "github.com/roysitumorang/sadia/modules/jwt/model"
)

type (
	JwtQuery interface {
		CreateJWT(ctx context.Context, tx pgx.Tx, request jwtModel.JsonWebToken) error
		DeleteJWTs(ctx context.Context, tx pgx.Tx, filter *jwtModel.DeleteFilter) (int64, error)
		FindJWTs(ctx context.Context, filter *jwtModel.Filter) ([]*jwtModel.JsonWebToken, int64, int64, error)
	}
)
