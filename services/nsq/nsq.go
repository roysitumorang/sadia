package nsq

import (
	"context"

	"github.com/goccy/go-json"
	"github.com/nsqio/go-nsq"
	"github.com/roysitumorang/sadia/helper"
	"go.uber.org/zap"
)

type (
	Producer struct {
		client *nsq.Producer
	}

	Consumer struct {
		client  *nsq.Consumer
		address string
	}
)

func NewConfig() *nsq.Config {
	return nsq.NewConfig()
}

func NewProducer(ctx context.Context, addr string, config *nsq.Config) (*Producer, error) {
	ctxt := "ServiceNSQ-NewProducer"
	client, err := nsq.NewProducer(addr, config)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrNewProducer")
		return nil, err
	}
	return &Producer{client: client}, nil
}

func (q *Producer) Ping(ctx context.Context) error {
	ctxt := "ServiceNSQ-Ping"
	err := q.client.Ping()
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrPing")
	}
	return err
}

func (q *Producer) Publish(ctx context.Context, topic string, messages ...interface{}) error {
	ctxt := "ServiceNSQ-Publish"
	n := len(messages)
	if n == 0 {
		return nil
	}
	body := make([][]byte, n)
	for i, message := range messages {
		messageByte, err := json.Marshal(message)
		if err != nil {
			return nil
		}
		body[i] = messageByte
	}
	err := q.client.MultiPublish(topic, body)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrMultiPublish")
	}
	return err
}

func NewConsumer(ctx context.Context, address, topic, channel string, config *nsq.Config) (*Consumer, error) {
	ctxt := "ServiceNSQ-NewConsumer"
	client, err := nsq.NewConsumer(topic, channel, config)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrNewConsumer")
		return nil, err
	}
	return &Consumer{client: client, address: address}, nil
}

func (q *Consumer) AddHandler(ctx context.Context, handler nsq.HandlerFunc) error {
	ctxt := "ServiceNSQ-AddHandler"
	q.client.AddHandler(handler)
	err := q.client.ConnectToNSQD(q.address)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrConnectToNSQD")
	}
	return err
}
