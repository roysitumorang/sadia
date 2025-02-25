package query

import (
	"context"

	"github.com/roysitumorang/sadia/helper"
	sequenceModel "github.com/roysitumorang/sadia/modules/sequence/model"
	sequenceQuery "github.com/roysitumorang/sadia/modules/sequence/query"
	"go.uber.org/zap"
)

type (
	sequenceUseCase struct {
		sequenceQuery sequenceQuery.SequenceQuery
	}
)

func New(
	sequenceQuery sequenceQuery.SequenceQuery,
) SequenceUseCase {
	return &sequenceUseCase{
		sequenceQuery: sequenceQuery,
	}
}

func (q *sequenceUseCase) SaveSequence(ctx context.Context, name, savedBy string) (*sequenceModel.Sequence, error) {
	ctxt := "SequenceQuery-SaveSequence"
	response, err := q.sequenceQuery.SaveSequence(ctx, name, savedBy)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSaveSequence")
	}
	return response, nil
}
