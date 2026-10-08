package services

import (
	"context"

	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/repositories"
	"go.uber.org/zap"
)

type SequenceService interface {
	SaveSequence(ctx context.Context, name string, savedBy uint64) (*models.Sequence, error)
}

type sequenceService struct {
	sequenceRepository repositories.SequenceRepository
}

func NewSequenceService(
	sequenceRepository repositories.SequenceRepository,
) SequenceService {
	return &sequenceService{
		sequenceRepository: sequenceRepository,
	}
}

func (q *sequenceService) SaveSequence(ctx context.Context, name string, savedBy uint64) (*models.Sequence, error) {
	ctxt := "SequenceService-SaveSequence"
	response, err := q.sequenceRepository.SaveSequence(ctx, name, savedBy)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSaveSequence")
	}
	return response, nil
}
