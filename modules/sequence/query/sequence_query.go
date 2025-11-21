package query

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/roysitumorang/sadia/helper"
	sequenceModel "github.com/roysitumorang/sadia/modules/sequence/model"
	"go.uber.org/zap"
)

type (
	sequenceQuery struct {
		dbRead,
		dbWrite *pgxpool.Pool
	}
)

func New(
	dbRead,
	dbWrite *pgxpool.Pool,
) SequenceQuery {
	return &sequenceQuery{
		dbRead:  dbRead,
		dbWrite: dbWrite,
	}
}

func (q *sequenceQuery) SaveSequence(ctx context.Context, name string, savedBy int64) (*sequenceModel.Sequence, error) {
	ctxt := "SequenceQuery-SaveSequence"
	snowflakeID := helper.GenerateSnowflakeID()
	now := time.Now()
	var response sequenceModel.Sequence
	if err := q.dbWrite.QueryRow(
		ctx,
		`INSERT INTO sequences (
			id
			, name
			, number
			, created_by
			, created_at
			, updated_by
			, updated_at
		) VALUES ($1, $2, $3, $4, $5, $4, $5)
		ON CONFLICT (name) DO UPDATE SET
			number = sequences.number + 1
		RETURNING id
			, name
			, number
			, created_by
			, created_at
			, updated_by
			, updated_at`,
		snowflakeID,
		name,
		1,
		savedBy,
		now,
	).Scan(
		&response.ID,
		&response.Name,
		&response.Number,
		&response.CreatedBy,
		&response.CreatedAt,
		&response.UpdatedBy,
		&response.UpdatedAt,
	); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
		return nil, err
	}
	return &response, nil
}
