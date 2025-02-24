package usecase

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/models"
	jwtModel "github.com/roysitumorang/sadia/modules/jwt/model"
)

type (
	JwtUseCase interface {
		CreateJWT(ctx context.Context, tx pgx.Tx, request jwtModel.JsonWebToken) error
		DeleteJWTs(ctx context.Context, tx pgx.Tx, maxExpiredAt time.Time, accountID string, jwtIDs ...string) (int64, error)
		FindJWTs(ctx context.Context, filter *jwtModel.Filter) ([]*jwtModel.JsonWebToken, *models.Pagination, error)
		ConsumeMessage(ctx context.Context) error
	}
)
