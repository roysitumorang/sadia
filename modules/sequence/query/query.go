package query

import (
	"context"

	sequenceModel "github.com/roysitumorang/sadia/modules/sequence/model"
)

type (
	SequenceQuery interface {
		SaveSequence(ctx context.Context, name string, savedBy string) (*sequenceModel.Sequence, error)
	}
)
