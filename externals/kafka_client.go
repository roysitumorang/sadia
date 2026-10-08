package externals

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/goccy/go-json"
	"github.com/roysitumorang/sadia/config"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	"github.com/twmb/franz-go/pkg/kgo"
	"go.uber.org/zap"
)

type KafkaClient struct {
	client *kgo.Client
}

type KafkaTopic struct {
	Name     string
	Payloads []map[string]any
}

func NewKafkaClient(ctx context.Context, brokers []string) (*KafkaClient, error) {
	ctxt := "KafkaClient-NewKafkaClient"
	client, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.ConsumerGroup(config.AppName),
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
	return &KafkaClient{client: client}, nil
}

func (s *KafkaClient) Ping(ctx context.Context) (err error) {
	ctxt := "KafkaClient-Ping"
	if err = s.client.Ping(ctx); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrPing")
	}
	return
}

func (s *KafkaClient) Publish(ctx context.Context, request ...KafkaTopic) (err error) {
	ctxt := "KafkaClient-Publish"
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

func (s *KafkaClient) PollFetches(ctx context.Context) kgo.Fetches {
	return s.client.PollFetches(ctx)
}

func (s *KafkaClient) CommitUncommittedOffsets(ctx context.Context) (err error) {
	ctxt := "KafkaClient-CommitUncommittedOffsets"
	if err = s.client.CommitUncommittedOffsets(ctx); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrCommitUncommittedOffsets")
	}
	return
}

func (s *KafkaClient) AllowRebalance() {
	s.client.AllowRebalance()
}
