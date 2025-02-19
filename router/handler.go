package router

import (
	"context"

	"github.com/roysitumorang/sadia/config"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/migration"
	accountQuery "github.com/roysitumorang/sadia/modules/account/query"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	jwtQuery "github.com/roysitumorang/sadia/modules/jwt/query"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	"go.uber.org/zap"
)

type (
	Service struct {
		Migration      *migration.Migration
		AccountUseCase accountUseCase.AccountUseCase
		JwtUseCase     jwtUseCase.JwtUseCase
	}
)

func MakeHandler(ctx context.Context) (*Service, error) {
	ctxt := "Router-MakeHandler"
	dbRead, err := config.GetDbReadOnly(ctx)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrGetDbReadOnly")
		return nil, err
	}
	dbWrite, err := config.GetDbWriteOnly(ctx)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrGetDbWriteOnly")
		return nil, err
	}
	migration := migration.New(dbRead, dbWrite)
	accountQuery := accountQuery.New(dbRead, dbWrite)
	jwtQuery := jwtQuery.New(dbRead, dbWrite)
	accountUseCase := accountUseCase.New(accountQuery)
	jwtUseCase := jwtUseCase.New(jwtQuery)
	return &Service{
		Migration:      migration,
		AccountUseCase: accountUseCase,
		JwtUseCase:     jwtUseCase,
	}, nil
}
