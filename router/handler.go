package router

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/storage/valkey"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/roysitumorang/sadia/config"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/migration"
	"github.com/roysitumorang/sadia/models"
	accountQuery "github.com/roysitumorang/sadia/modules/account/query"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	companyQuery "github.com/roysitumorang/sadia/modules/company/query"
	companyUseCase "github.com/roysitumorang/sadia/modules/company/usecase"
	jwtQuery "github.com/roysitumorang/sadia/modules/jwt/query"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	logQuery "github.com/roysitumorang/sadia/modules/log/query"
	logUseCase "github.com/roysitumorang/sadia/modules/log/usecase"
	productQuery "github.com/roysitumorang/sadia/modules/product/query"
	productUseCase "github.com/roysitumorang/sadia/modules/product/usecase"
	productCategoryQuery "github.com/roysitumorang/sadia/modules/product_category/query"
	productCategoryUseCase "github.com/roysitumorang/sadia/modules/product_category/usecase"
	sequenceQuery "github.com/roysitumorang/sadia/modules/sequence/query"
	sequenceUseCase "github.com/roysitumorang/sadia/modules/sequence/usecase"
	sessionQuery "github.com/roysitumorang/sadia/modules/session/query"
	sessionUseCase "github.com/roysitumorang/sadia/modules/session/usecase"
	transactionQuery "github.com/roysitumorang/sadia/modules/transaction/query"
	transactionUseCase "github.com/roysitumorang/sadia/modules/transaction/usecase"
	"github.com/roysitumorang/sadia/services/kafka"
	"go.uber.org/zap"
)

type (
	Service struct {
		DbWrite                *pgxpool.Pool
		Migration              *migration.Migration
		KafkaService           *kafka.KafkaService
		Storage                fiber.Storage
		AccountUseCase         accountUseCase.AccountUseCase
		JwtUseCase             jwtUseCase.JwtUseCase
		CompanyUseCase         companyUseCase.CompanyUseCase
		LogUseCase             logUseCase.LogUseCase
		ProductCategoryUseCase productCategoryUseCase.ProductCategoryUseCase
		ProductUseCase         productUseCase.ProductUseCase
		SessionUseCase         sessionUseCase.SessionUseCase
		SequenceUseCase        sequenceUseCase.SequenceUseCase
		TransactionUseCase     transactionUseCase.TransactionUseCase
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
	kafkaService, err := kafka.New(ctx, strings.Split(os.Getenv("KAFKA_BROKERS"), ","))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNew")
		return nil, err
	}
	if err = kafkaService.Ping(ctx); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrPing")
		return nil, err
	}
	topics := make([]kafka.Topic, len(models.SliceTopics))
	for i, topic := range models.SliceTopics {
		topics[i] = kafka.Topic{
			Name:     topic,
			Payloads: []map[string]any{},
		}
	}
	_ = kafkaService.Publish(ctx, topics...)
	storage := valkey.New(valkey.Config{
		URL: os.Getenv("REDIS_URL"),
	})
	accountQuery := accountQuery.New(dbRead, dbWrite)
	jwtQuery := jwtQuery.New(dbRead, dbWrite)
	companyQuery := companyQuery.New(dbRead, dbWrite)
	logQuery := logQuery.New(dbRead, dbWrite)
	productCategoryQuery := productCategoryQuery.New(dbRead, dbWrite)
	productQuery := productQuery.New(dbRead, dbWrite)
	sessionQuery := sessionQuery.New(dbRead, dbWrite)
	sequenceQuery := sequenceQuery.New(dbRead, dbWrite)
	transactionQuery := transactionQuery.New(dbRead, dbWrite)
	accountUseCase := accountUseCase.New(accountQuery)
	jwtUseCase := jwtUseCase.New(jwtQuery)
	companyUseCase := companyUseCase.New(companyQuery)
	logUseCase := logUseCase.New(logQuery)
	productCategoryUseCase := productCategoryUseCase.New(productCategoryQuery)
	productUseCase := productUseCase.New(productQuery)
	sessionUseCase := sessionUseCase.New(sessionQuery)
	sequenceUseCase := sequenceUseCase.New(sequenceQuery)
	transactionUseCase := transactionUseCase.New(transactionQuery)
	return &Service{
		DbWrite:                dbWrite,
		Migration:              migration,
		KafkaService:           kafkaService,
		Storage:                storage,
		AccountUseCase:         accountUseCase,
		JwtUseCase:             jwtUseCase,
		LogUseCase:             logUseCase,
		CompanyUseCase:         companyUseCase,
		ProductCategoryUseCase: productCategoryUseCase,
		ProductUseCase:         productUseCase,
		SessionUseCase:         sessionUseCase,
		SequenceUseCase:        sequenceUseCase,
		TransactionUseCase:     transactionUseCase,
	}, nil
}

func (q *Service) Consume(ctx context.Context) error {
	ctxt := "Router-Consume"
	defer func() {
		if r := recover(); r != nil {
			err, ok := r.(error)
			if !ok {
				err = fmt.Errorf("%v", r)
			}
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrRecover")
		}
	}()
	for {
		fetches := q.KafkaService.PollFetches(ctx)
		if fetches.IsClientClosed() {
			return nil
		}
		if errs := fetches.Errors(); len(errs) > 0 {
			err := errors.New(fmt.Sprint(errs))
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrPollFetches")
			return err
		}
		records := fetches.Records()
		if err := q.KafkaService.CommitUncommittedOffsets(ctx); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrCommitUncommittedOffsets")
			return err
		}
		q.KafkaService.AllowRebalance()
		for _, record := range records {
			now := time.Now()
			if err := q.AccountUseCase.ConsumeMessage(ctx, record.Topic, record.Value); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrConsumeMessage")
			}
			if err := q.CompanyUseCase.ConsumeMessage(ctx, record.Topic, record.Value); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrConsumeMessage")
			}
			if err := q.JwtUseCase.ConsumeMessage(ctx, record.Topic, record.Value); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrConsumeMessage")
			}
			if err := q.ProductUseCase.ConsumeMessage(ctx, record.Topic, record.Value); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrConsumeMessage")
			}
			if err := q.ProductCategoryUseCase.ConsumeMessage(ctx, record.Topic, record.Value); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrConsumeMessage")
			}
			if err := q.SessionUseCase.ConsumeMessage(ctx, record.Topic, record.Value); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrConsumeMessage")
			}
			if err := q.TransactionUseCase.ConsumeMessage(ctx, record.Topic, record.Value); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrConsumeMessage")
			}
			duration := time.Since(now)
			helper.Log(ctx, zap.InfoLevel, fmt.Sprintf("consumed message on topic %s[%d]@%d: %s in %s", record.Topic, record.Partition, record.Offset, record.Value, duration.String()), ctxt, "")
		}
	}
}
