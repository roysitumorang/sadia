package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

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

func (q *jwtUseCase) DeleteJWTs(ctx context.Context, tx pgx.Tx, maxExpiredAt time.Time, accountID int64, jwtIDs ...string) (int64, error) {
	ctxt := "JwtUseCase-DeleteJWTs"
	rowsAffected, err := q.jwtQuery.DeleteJWTs(ctx, tx, maxExpiredAt, accountID, jwtIDs...)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteJWTs")
	}
	return rowsAffected, err
}

func (q *jwtUseCase) FindJWTs(ctx context.Context, filter *jwtModel.Filter, urlValues url.Values) ([]*jwtModel.JsonWebToken, *models.Pagination, error) {
	ctxt := "JwtUseCase-FindJWTs"
	rows, total, pages, err := q.jwtQuery.FindJWTs(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindJWTs")
		return nil, nil, err
	}
	pagination, err := helper.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, urlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *jwtUseCase) ConsumeMessage(ctx context.Context) error {
	ctxt := "JwtUseCase-ConsumeMessage"
	helper.Log(ctx, zap.InfoLevel, fmt.Sprintf("consume topic %s", config.TopicJwt), ctxt, "")
	err := q.nsqConsumer.AddHandler(ctx, func(message *nsq.Message) error {
		helper.Log(ctx, zap.InfoLevel, helper.ByteSlice2String(message.Body), ctxt, "")
		if json.Valid(message.Body) {
			var body models.Message
			err := json.Unmarshal(message.Body, &body)
			if err != nil {
				message.Requeue(-1)
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrUnmarshal")
				return err
			}
		}
		message.Finish()
		return nil
	})
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrAddHandler")
	}
	return err
}
