package kafka

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/goccy/go-json"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	"github.com/twmb/franz-go/pkg/kgo"
	"go.uber.org/zap"
)

type (
	KafkaService struct {
		client *kgo.Client
	}

	Topic struct {
		Name     string
		Payloads []map[string]any
	}
)

func New(ctx context.Context, brokers []string) (*KafkaService, error) {
	ctxt := "KafkaService-New"
	client, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.ConsumerGroup("notification"),
		kgo.AllowAutoTopicCreation(),
		kgo.ConsumeTopics(models.SliceTopics...),
		kgo.DisableAutoCommit(),
		kgo.BlockRebalanceOnPoll(),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrNewClient")
		return nil, err
	}
	return &KafkaService{client: client}, nil
}

func (s *KafkaService) Ping(ctx context.Context) (err error) {
	ctxt := "KafkaService-Ping"
	if err = s.client.Ping(ctx); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrPing")
	}
	return
}

func (s *KafkaService) Publish(ctx context.Context, request ...Topic) (err error) {
	ctxt := "KafkaService-Publish"
	n := len(request)
	if n == 0 {
		return
	}
	now := time.Now()
	var wg sync.WaitGroup
	for _, topic := range request {
		for _, payload := range topic.Payloads {
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrMarshal")
				return err
			}
			wg.Add(1)
			record := &kgo.Record{
				Topic: topic.Name,
				Value: payloadJSON,
			}
			s.client.Produce(ctx, record, func(result *kgo.Record, err error) {
				defer wg.Done()
				if err != nil {
					helper.Capture(ctx, zap.ErrorLevel, fmt.Errorf("publish message failed: %v", err), ctxt, "ErrProduce")
					return
				}
				helper.Log(ctx, zap.InfoLevel, fmt.Sprintf("published message to topic %s[%d]@%d: %s in %s", result.Topic, result.Partition, result.Offset, result.Value, time.Since(now).String()), ctxt, "")
			})
		}
	}
	wg.Wait()
	if err = s.client.Flush(ctx); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrFlush")
	}
	return
}

func (s *KafkaService) PollFetches(ctx context.Context) kgo.Fetches {
	return s.client.PollFetches(ctx)
}

func (s *KafkaService) CommitUncommittedOffsets(ctx context.Context) (err error) {
	ctxt := "KafkaService-CommitUncommittedOffsets"
	if err = s.client.CommitUncommittedOffsets(ctx); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrCommitUncommittedOffsets")
	}
	return
}

func (s *KafkaService) AllowRebalance() {
	s.client.AllowRebalance()
}
