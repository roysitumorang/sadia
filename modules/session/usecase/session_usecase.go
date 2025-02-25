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
	sessionModel "github.com/roysitumorang/sadia/modules/session/model"
	sessionQuery "github.com/roysitumorang/sadia/modules/session/query"
	serviceNsq "github.com/roysitumorang/sadia/services/nsq"
	"go.uber.org/zap"
)

type (
	sessionUseCase struct {
		sessionQuery sessionQuery.SessionQuery
		nsqConsumer  *serviceNsq.Consumer
	}
)

func New(
	ctx context.Context,
	sessionQuery sessionQuery.SessionQuery,
	nsqAddress string,
	nsqConfig *nsq.Config,
) (SessionUseCase, error) {
	ctxt := "SessionCategoryUseCase-New"
	nsqConsumer, err := serviceNsq.NewConsumer(ctx, nsqAddress, config.TopicSession, config.NsqChannel, nsqConfig)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrNewConsumer")
		return nil, err
	}
	return &sessionUseCase{
		sessionQuery: sessionQuery,
		nsqConsumer:  nsqConsumer,
	}, nil
}

func (q *sessionUseCase) FindSessions(ctx context.Context, filter *sessionModel.Filter) ([]*sessionModel.Session, *models.Pagination, error) {
	ctxt := "SessionUseCase-FindSessions"
	sessionCategories, total, pages, err := q.sessionQuery.FindSessions(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindSessions")
		return nil, nil, err
	}
	n := len(sessionCategories)
	rows := make([]*sessionModel.Session, n)
	if n > 0 {
		copy(rows, sessionCategories)
	}
	pagination, err := helper.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *sessionUseCase) CreateSession(ctx context.Context, tx pgx.Tx, request *sessionModel.NewSession) (*sessionModel.Session, error) {
	ctxt := "SessionUseCase-CreateSession"
	response, err := q.sessionQuery.CreateSession(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateSession")
	}
	return response, err
}

func (q *sessionUseCase) UpdateSession(ctx context.Context, tx pgx.Tx, request *sessionModel.Session) error {
	ctxt := "SessionUseCase-UpdateSession"
	err := q.sessionQuery.UpdateSession(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateSession")
	}
	return err
}

func (q *sessionUseCase) ConsumeMessage(ctx context.Context) error {
	ctxt := "SessionUseCase-ConsumeMessage"
	var counter uint64
	helper.Log(ctx, zap.InfoLevel, fmt.Sprintf("consume topic %s", config.TopicSession), ctxt, "")
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
				config.TopicSession,
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
