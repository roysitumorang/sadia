package migrations

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/roysitumorang/sadia/helper"
	"go.uber.org/zap"
)

type Migration struct {
	dbRead,
	dbWrite *pgxpool.Pool
}

var Migrations = map[uint64]func(ctx context.Context, tx pgx.Tx) error{}

func New(
	dbRead,
	dbWrite *pgxpool.Pool,
) *Migration {
	return &Migration{
		dbRead:  dbRead,
		dbWrite: dbWrite,
	}
}

func (m *Migration) Migrate(ctx context.Context) error {
	ctxt := "Migration-Migrate"
	if _, err := m.dbWrite.Exec(
		ctx,
		`CREATE TABLE IF NOT EXISTS migrations (
			"version" uint8 NOT NULL PRIMARY KEY
		)`,
	); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
		return err
	}
	rows, err := m.dbRead.Query(ctx, `SELECT "version" FROM "migrations" ORDER BY "version"`)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrQuery")
		return err
	}
	defer rows.Close()
	var version uint64
	mapVersions := map[uint64]struct{}{}
	for rows.Next() {
		if err = rows.Scan(&version); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return err
		}
		mapVersions[version] = struct{}{}
	}
	if err = rows.Err(); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrErr")
		return err
	}
	sortedVersions := slices.Collect(maps.Keys(Migrations))
	slices.Sort(sortedVersions)
	tx, err := m.dbWrite.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.Serializable,
	})
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrBeginTx")
		return err
	}
	defer func(ctx context.Context) {
		if err = tx.Rollback(ctx); errors.Is(err, pgx.ErrTxClosed) {
			err = nil
		}
		if err != nil {
			helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrRollback")
		}
	}(ctx)
	for _, version := range sortedVersions {
		if _, ok := mapVersions[version]; ok {
			continue
		}
		function, ok := Migrations[version]
		if !ok {
			return fmt.Errorf("migration function for version %d not found", version)
		}
		if err := function(ctx, tx); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrFunction")
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO "migrations" ("version") VALUES ($1)`, version); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			return err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrCommit")
	}
	return err
}

func (m *Migration) CreateMigrationFile() error {
	now := time.Now().UTC().UnixNano()
	filepath := helper.Sprintf("./migrations/%d.go", now)
	content := helper.Sprintf(
		`package migrations

import (
	"context"

	"github.com/jackc/pgx/v5"
)

func init() {
	Migrations[%d] = func(ctx context.Context, tx pgx.Tx) (err error) {
		ctxt := "Migrations-%d"
		return
	}
}`,
		now,
		now,
	)
	return os.WriteFile(
		filepath,
		helper.String2ByteSlice(content),
		0600,
	)
}
