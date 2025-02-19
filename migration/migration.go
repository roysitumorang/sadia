package migration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/roysitumorang/sadia/helper"
	"go.uber.org/zap"
)

type (
	Migration struct {
		dbRead,
		dbWrite *pgxpool.Pool
	}
)

var (
	Migrations = map[int64]func(ctx context.Context, tx pgx.Tx) error{}
)

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
			"version" bigint NOT NULL PRIMARY KEY
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
	mapVersions := map[int64]int{}
	for rows.Next() {
		var version int64
		if err := rows.Scan(&version); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrScan")
			return err
		}
		mapVersions[version] = 1
	}
	sortedVersions := make([]int64, len(Migrations))
	var i int
	for version := range Migrations {
		sortedVersions[i] = version
		i++
	}
	if len(sortedVersions) > 0 {
		sort.Slice(
			sortedVersions,
			func(i, j int) bool {
				return sortedVersions[i] < sortedVersions[j]
			},
		)
	}
	tx, err := m.dbWrite.Begin(ctx)
	if err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrBegin")
		return err
	}
	for _, version := range sortedVersions {
		if _, ok := mapVersions[version]; ok {
			continue
		}
		function, ok := Migrations[version]
		if !ok {
			err := fmt.Errorf("migration function for version %d not found", version)
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrOK")
			if errRollback := tx.Rollback(ctx); errRollback != nil {
				helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
			}
			return err
		}
		if err := function(ctx, tx); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrFunction")
			if errRollback := tx.Rollback(ctx); errRollback != nil {
				helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO "migrations" ("version") VALUES ($1)`, version); err != nil {
			helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExec")
			if errRollback := tx.Rollback(ctx); errRollback != nil {
				helper.Capture(ctx, zap.ErrorLevel, errRollback, ctxt, "ErrRollback")
			}
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrCommit")
		return err
	}
	return nil
}

func (m *Migration) CreateMigrationFile(_ context.Context) error {
	now := time.Now().UTC().UnixNano()
	filepath := fmt.Sprintf("./migration/%d.go", now)
	content := fmt.Sprintf(
		`package migration

import (
	"context"

	"github.com/jackc/pgx/v5"
)

func init() {
	Migrations[%d] = func(ctx context.Context, tx pgx.Tx) (err error) {
		ctxt := "Migration-%d"
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
