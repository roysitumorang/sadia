package repositories

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	"go.uber.org/zap"
)

type SequenceRepository interface {
	SaveSequence(ctx context.Context, name string, savedBy uint64) (*models.Sequence, error)
}

type sequenceRepository struct {
	dbRead,
	dbWrite *pgxpool.Pool
}

func NewSequenceRepository(
	dbRead,
	dbWrite *pgxpool.Pool,
) SequenceRepository {
	return &sequenceRepository{
		dbRead:  dbRead,
		dbWrite: dbWrite,
	}
}

func (q *sequenceRepository) SaveSequence(ctx context.Context, name string, savedBy uint64) (*models.Sequence, error) {
	ctxt := "SequenceRepository-SaveSequence"
	now := time.Now()
	var response models.Sequence
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
		helper.GenerateSnowflakeID(),
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
