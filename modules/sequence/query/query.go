package query

import (
	"context"

	sequenceModel "github.com/roysitumorang/sadia/modules/sequence/model"
)

type (
	SequenceQuery interface {
		SaveSequence(ctx context.Context, name string, savedBy int64) (*sequenceModel.Sequence, error)
	}
)
