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
	"github.com/roysitumorang/sadia/services/nsq"
	"go.uber.org/zap"
)

type (
	Service struct {
		Migration      *migration.Migration
		NsqProducer    *nsq.Producer
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
	nsqAddress := helper.GetNsqAddress()
	nsqConfig := nsq.NewConfig()
	nsqProducer, err := nsq.NewProducer(ctx, nsqAddress, nsqConfig)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNewProducer")
		return nil, err
	}
	if err := nsqProducer.Ping(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrPing")
		return nil, err
	}
	accountQuery := accountQuery.New(dbRead, dbWrite)
	jwtQuery := jwtQuery.New(dbRead, dbWrite)
	accountUseCase, err := accountUseCase.New(ctx, accountQuery, nsqAddress, nsqConfig)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNew")
		return nil, err
	}
	jwtUseCase, err := jwtUseCase.New(ctx, jwtQuery, nsqAddress, nsqConfig)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNew")
		return nil, err
	}
	return &Service{
		Migration:      migration,
		NsqProducer:    nsqProducer,
		AccountUseCase: accountUseCase,
		JwtUseCase:     jwtUseCase,
	}, nil
}
