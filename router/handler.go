package router

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/roysitumorang/sadia/config"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/migration"
	accountQuery "github.com/roysitumorang/sadia/modules/account/query"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	companyQuery "github.com/roysitumorang/sadia/modules/company/query"
	companyUseCase "github.com/roysitumorang/sadia/modules/company/usecase"
	jwtQuery "github.com/roysitumorang/sadia/modules/jwt/query"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	productQuery "github.com/roysitumorang/sadia/modules/product/query"
	productUseCase "github.com/roysitumorang/sadia/modules/product/usecase"
	productCategoryQuery "github.com/roysitumorang/sadia/modules/product_category/query"
	productCategoryUseCase "github.com/roysitumorang/sadia/modules/product_category/usecase"
	storeQuery "github.com/roysitumorang/sadia/modules/store/query"
	storeUseCase "github.com/roysitumorang/sadia/modules/store/usecase"
	serviceNsq "github.com/roysitumorang/sadia/services/nsq"
	"go.uber.org/zap"
)

type (
	Service struct {
		DbWrite                *pgxpool.Pool
		Migration              *migration.Migration
		NsqProducer            *serviceNsq.Producer
		AccountUseCase         accountUseCase.AccountUseCase
		JwtUseCase             jwtUseCase.JwtUseCase
		CompanyUseCase         companyUseCase.CompanyUseCase
		ProductCategoryUseCase productCategoryUseCase.ProductCategoryUseCase
		ProductUseCase         productUseCase.ProductUseCase
		StoreUseCase           storeUseCase.StoreUseCase
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
	nsqConfig := serviceNsq.NewConfig()
	nsqProducer, err := serviceNsq.NewProducer(ctx, nsqAddress, nsqConfig)
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
	companyQuery := companyQuery.New(dbRead, dbWrite)
	productCategoryQuery := productCategoryQuery.New(dbRead, dbWrite)
	productQuery := productQuery.New(dbRead, dbWrite)
	storeQuery := storeQuery.New(dbRead, dbWrite)
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
	companyUseCase, err := companyUseCase.New(ctx, companyQuery, nsqAddress, nsqConfig)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNew")
		return nil, err
	}
	productCategoryUseCase, err := productCategoryUseCase.New(ctx, productCategoryQuery, nsqAddress, nsqConfig)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNew")
		return nil, err
	}
	productUseCase, err := productUseCase.New(ctx, productQuery, nsqAddress, nsqConfig)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNew")
		return nil, err
	}
	storeUseCase, err := storeUseCase.New(ctx, storeQuery, nsqAddress, nsqConfig)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNew")
		return nil, err
	}
	return &Service{
		DbWrite:                dbWrite,
		Migration:              migration,
		NsqProducer:            nsqProducer,
		AccountUseCase:         accountUseCase,
		JwtUseCase:             jwtUseCase,
		CompanyUseCase:         companyUseCase,
		ProductCategoryUseCase: productCategoryUseCase,
		ProductUseCase:         productUseCase,
		StoreUseCase:           storeUseCase,
	}, nil
}
