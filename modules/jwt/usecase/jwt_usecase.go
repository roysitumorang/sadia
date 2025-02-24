package usecase

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/goccy/go-json"
	"github.com/jackc/pgx/v5"
	"github.com/nsqio/go-nsq"
	"github.com/roysitumorang/sadia/config"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	jwtModel "github.com/roysitumorang/sadia/modules/jwt/model"
	jwtQuery "github.com/roysitumorang/sadia/modules/jwt/query"
	serviceNsq "github.com/roysitumorang/sadia/services/nsq"
	"go.uber.org/zap"
)

type (
	jwtUseCase struct {
		jwtQuery    jwtQuery.JwtQuery
		nsqConsumer *serviceNsq.Consumer
	}
)

func New(
	ctx context.Context,
	jwtQuery jwtQuery.JwtQuery,
	nsqAddress string,
	nsqConfig *nsq.Config,
) (JwtUseCase, error) {
	ctxt := "JwtUseCase-New"
	nsqConsumer, err := serviceNsq.NewConsumer(ctx, nsqAddress, config.TopicJwt, config.NsqChannel, nsqConfig)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNewConsumer")
		return nil, err
	}
	return &jwtUseCase{
		jwtQuery:    jwtQuery,
		nsqConsumer: nsqConsumer,
	}, nil
}

func (q *jwtUseCase) CreateJWT(ctx context.Context, tx pgx.Tx, request jwtModel.JsonWebToken) error {
	ctxt := "JwtUseCase-CreateJWT"
	err := q.jwtQuery.CreateJWT(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJwt")
	}
	return err
}

func (q *jwtUseCase) DeleteJWTs(ctx context.Context, tx pgx.Tx, maxExpiredAt time.Time, accountID string, jwtIDs ...string) (int64, error) {
	ctxt := "JwtUseCase-DeleteJWTs"
	rowsAffected, err := q.jwtQuery.DeleteJWTs(ctx, tx, maxExpiredAt, accountID, jwtIDs...)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
	}
	return rowsAffected, err
}

func (q *jwtUseCase) FindJWTs(ctx context.Context, filter *jwtModel.Filter) ([]*jwtModel.JsonWebToken, *models.Pagination, error) {
	ctxt := "JwtUseCase-FindJWTs"
	jsonWebTokens, total, pages, err := q.jwtQuery.FindJWTs(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindJWTs")
		return nil, nil, err
	}
	n := len(jsonWebTokens)
	rows := make([]*jwtModel.JsonWebToken, n)
	if n > 0 {
		copy(rows, jsonWebTokens)
	}
	pagination, err := helper.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *jwtUseCase) ConsumeMessage(ctx context.Context) error {
	ctxt := "JwtUseCase-ConsumeMessage"
	var counter uint64
	helper.Log(ctx, zap.InfoLevel, fmt.Sprintf("consume topic %s", config.TopicJwt), ctxt, "")
	err := q.nsqConsumer.AddHandler(ctx, func(message *nsq.Message) error {

		now := time.Now()
		atomic.AddUint64(&counter, 1)
		var body models.Message
		if err := json.Unmarshal(message.Body, &body); err != nil {
			message.Finish()
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrUnmarshal")
			return nil
		}
		message.Finish()
		duration := time.Since(now)
		helper.Log(
			ctx,
			zap.InfoLevel,
			fmt.Sprintf(
				"message on topic %s@%d: %s, consumed in %s",
				config.TopicJwt,
				atomic.LoadUint64(&counter),
				helper.ByteSlice2String(message.Body),
				duration.String(),
			),
			ctxt,
			"",
		)
		return nil
	})
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrAddHandler")
	}
	return err
}
