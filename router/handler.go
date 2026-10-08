package router

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/storage/valkey"
	"github.com/roysitumorang/sadia/config"
	"github.com/roysitumorang/sadia/externals"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/migrations"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/repositories"
	"github.com/roysitumorang/sadia/services"
	"go.uber.org/zap"
)

type Service struct {
	Migration              *migrations.Migration
	KafkaClient            *externals.KafkaClient
	Storage                fiber.Storage
	AccountService         services.AccountService
	JwtService             services.JwtService
	CompanyService         services.CompanyService
	LogService             services.LogService
	ProductCategoryService services.ProductCategoryService
	ProductService         services.ProductService
	SessionService         services.SessionService
	SequenceService        services.SequenceService
	TransactionService     services.TransactionService
}

func MakeHandler(ctx context.Context) (*Service, error) {
	ctxt := "Router-MakeHandler"
	envMaxConns, ok := os.LookupEnv("DB_MAX_CONNECTIONS")
	if !ok || envMaxConns == "" {
		return nil, errors.New("db: env DB_MAX_CONNECTIONS is required")
	}
	conns, err := strconv.ParseInt(envMaxConns, 10, 32)
	if err != nil {
		return nil, err
	}
	if conns < 1 {
		return nil, errors.New("db: env DB_MAX_CONNECTIONS requires a positive integer")
	}
	maxConns := int32(conns)
	dbRead, err := config.CreateDbConnection(ctx, os.Getenv("DB_READ_URL"), maxConns)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrCreateDbConnection")
		return nil, err
	}
	dbWrite, err := config.CreateDbConnection(ctx, os.Getenv("DB_WRITE_URL"), maxConns)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrCreateDbConnection")
		return nil, err
	}
	repositories.SetDbWrite(dbWrite)
	migration := migrations.New(dbRead, dbWrite)
	kafkaClient, err := externals.NewKafkaClient(ctx, strings.Split(os.Getenv("KAFKA_BROKERS"), ","))
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNewKafkaClient")
		return nil, err
	}
	if err = kafkaClient.Ping(ctx); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrPing")
		return nil, err
	}
	topics := make([]externals.KafkaTopic, len(models.SliceTopics))
	for i, topic := range models.SliceTopics {
		topics[i] = externals.KafkaTopic{
			Name:     topic,
			Payloads: []map[string]any{},
		}
	}
	_ = kafkaClient.Publish(ctx, topics...)
	storage := valkey.New(valkey.Config{
		URL: os.Getenv("REDIS_URL"),
	})
	accountRepository := repositories.NewAccountRepository(dbRead, dbWrite)
	jwtRepository := repositories.NewJwtRepository(dbRead, dbWrite)
	companyRepository := repositories.NewCompanyRepository(dbRead, dbWrite)
	logRepository := repositories.NewLogRepository(dbRead, dbWrite)
	productCategoryRepository := repositories.NewProductCategoryRepository(dbRead, dbWrite)
	productRepository := repositories.NewProductRepository(dbRead, dbWrite)
	sessionRepository := repositories.NewSessionRepository(dbRead, dbWrite)
	sequenceRepository := repositories.NewSequenceRepository(dbRead, dbWrite)
	transactionRepository := repositories.NewTransactionRepository(dbRead, dbWrite)
	accountService := services.NewAccountService(accountRepository)
	jwtService := services.NewJwtService(jwtRepository)
	companyService := services.NewCompanyService(companyRepository)
	logService := services.NewLogService(logRepository)
	productCategoryService := services.NewProductCategoryService(productCategoryRepository)
	productService := services.NewProductService(productRepository)
	sessionService := services.NewSessionService(sessionRepository)
	sequenceService := services.NewSequenceService(sequenceRepository)
	transactionService := services.NewTransactionService(transactionRepository)
	return &Service{
		Migration:              migration,
		KafkaClient:            kafkaClient,
		Storage:                storage,
		AccountService:         accountService,
		JwtService:             jwtService,
		LogService:             logService,
		CompanyService:         companyService,
		ProductCategoryService: productCategoryService,
		ProductService:         productService,
		SessionService:         sessionService,
		SequenceService:        sequenceService,
		TransactionService:     transactionService,
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
		fetches := q.KafkaClient.PollFetches(ctx)
		if fetches.IsClientClosed() {
			return nil
		}
		if errs := fetches.Errors(); len(errs) > 0 {
			err := errors.New(fmt.Sprint(errs))
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrPollFetches")
			return err
		}
		records := fetches.Records()
		if err := q.KafkaClient.CommitUncommittedOffsets(ctx); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrCommitUncommittedOffsets")
			return err
		}
		q.KafkaClient.AllowRebalance()
		for _, record := range records {
			now := time.Now()
			if err := q.AccountService.ConsumeMessage(ctx, record.Topic, record.Value); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrConsumeMessage")
			}
			if err := q.CompanyService.ConsumeMessage(ctx, record.Topic, record.Value); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrConsumeMessage")
			}
			if err := q.JwtService.ConsumeMessage(ctx, record.Topic, record.Value); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrConsumeMessage")
			}
			if err := q.ProductService.ConsumeMessage(ctx, record.Topic, record.Value); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrConsumeMessage")
			}
			if err := q.ProductCategoryService.ConsumeMessage(ctx, record.Topic, record.Value); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrConsumeMessage")
			}
			if err := q.SessionService.ConsumeMessage(ctx, record.Topic, record.Value); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrConsumeMessage")
			}
			if err := q.TransactionService.ConsumeMessage(ctx, record.Topic, record.Value); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrConsumeMessage")
			}
			duration := time.Since(now)
			helper.Log(ctx, zap.InfoLevel, fmt.Sprintf("consumed message on topic %s[%d]@%d: %s in %s", record.Topic, record.Partition, record.Offset, record.Value, duration.String()), ctxt, "")
		}
	}
}
