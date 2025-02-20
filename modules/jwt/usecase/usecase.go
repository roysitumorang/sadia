package usecase

import (
	"context"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/models"
	jwtModel "github.com/roysitumorang/sadia/modules/jwt/model"
)

type (
	JwtUseCase interface {
		CreateJWT(ctx context.Context, tx pgx.Tx, request jwtModel.JsonWebToken) error
		DeleteJWTs(ctx context.Context, tx pgx.Tx, maxExpiredAt time.Time, accountUID string, jwtUIDs ...string) (int64, error)
		FindJWTs(ctx context.Context, filter *jwtModel.Filter, urlValues url.Values) ([]*jwtModel.JsonWebToken, *models.Pagination, error)
		ConsumeMessage(ctx context.Context) error
	}
)
