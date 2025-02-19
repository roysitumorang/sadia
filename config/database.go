package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	dataSourceName = "host=%s user=%s password=%s dbname=%s %s"
)

func GetDbWriteOnly(ctx context.Context) (*pgxpool.Pool, error) {
	return createDbConnection(
		ctx,
		os.Getenv("DB_WRITE_HOST"),
		os.Getenv("DB_WRITE_USERNAME"),
		os.Getenv("DB_WRITE_PASSWORD"),
		os.Getenv("DB_WRITE_NAME"),
		os.Getenv("DB_WRITE_PARAM"),
	)
}

func GetDbReadOnly(ctx context.Context) (*pgxpool.Pool, error) {
	return createDbConnection(
		ctx,
		os.Getenv("DB_READ_HOST"),
		os.Getenv("DB_READ_USERNAME"),
		os.Getenv("DB_READ_PASSWORD"),
		os.Getenv("DB_READ_NAME"),
		os.Getenv("DB_READ_PARAM"),
	)
}

func createDbConnection(ctx context.Context, host, user, password, dbName, param string) (*pgxpool.Pool, error) {
	descriptor := fmt.Sprintf(dataSourceName, host, user, password, dbName, param)
	envMaxConns, ok := os.LookupEnv("DB_MAX_CONNECTIONS")
	if !ok || envMaxConns == "" {
		return nil, errors.New("db: env DB_MAX_CONNECTIONS is required")
	}
	maxConns, err := strconv.Atoi(envMaxConns)
	if err != nil {
		return nil, err
	}
	if maxConns < 1 {
		return nil, errors.New("db: env DB_MAX_CONNECTIONS requires a positive integer")
	}
	config, err := pgxpool.ParseConfig(descriptor)
	if err != nil {
		return nil, err
	}
	config.MaxConns = int32(maxConns)
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(ctx); err != nil {
		return nil, err
	}
	return db, nil
}
