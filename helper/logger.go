package helper

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	topic   = "sadia-service-log"
	service = "sadia"
)

var (
	logger     *zap.Logger
	InitLogger = sync.OnceFunc(func() {
		encoderCfg := zap.NewProductionEncoderConfig()
		encoderCfg.TimeKey = "timestamp"
		encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
		logger = zap.Must(zap.Config{
			Level:             zap.NewAtomicLevelAt(zap.InfoLevel),
			Development:       false,
			DisableCaller:     true,
			DisableStacktrace: true,
			Sampling:          nil,
			Encoding:          "json",
			EncoderConfig:     encoderCfg,
			OutputPaths: []string{
				"stderr",
			},
			ErrorOutputPaths: []string{
				"stderr",
			},
			InitialFields: map[string]interface{}{},
		}.Build())
	})
)

func GetLogger() *zap.Logger {
	return logger
}

func logContext(_ context.Context, context, scope string) *zap.Logger {
	defer func() {
		_ = logger.Sync()
	}()
	fields := []zap.Field{
		zap.String("topic", topic),
		zap.String("context", context),
		zap.String("service", service),
	}
	if scope != "" {
		fields = append(fields, zap.String("scope", scope))
	}
	return logger.With(fields...)
}

func Log(ctx context.Context, level zapcore.Level, message, context, scope string) {
	entry := logContext(ctx, context, scope)
	switch level {
	case zap.DebugLevel:
		entry.Debug(message)
	case zap.InfoLevel:
		entry.Info(message)
	case zap.WarnLevel:
		entry.Warn(message)
	case zap.ErrorLevel:
		var name string
		pc, file, line, _ := runtime.Caller(1)
		if fn := runtime.FuncForPC(pc); fn != nil {
			name = fn.Name()
		}
		entry.Error(
			message,
			zap.String("func", name),
			zap.String("file", fmt.Sprintf("%s:%d", file, line)),
			zap.Int("line", line),
		)
	case zap.FatalLevel:
		entry.Fatal(message)
	case zap.PanicLevel:
		entry.Panic(message)
	}
}

func Capture(ctx context.Context, level zapcore.Level, err error, context, scope string) {
	entry := logContext(ctx, context, scope)
	switch level {
	case zap.DebugLevel:
		entry.Debug(err.Error())
	case zap.InfoLevel:
		entry.Info(err.Error())
	case zap.WarnLevel:
		entry.Warn(err.Error())
	case zap.ErrorLevel:
		// ignoring pgx.ErrNoRows
		if errors.Is(err, pgx.ErrNoRows) {
			return
		}
		var name string
		pc, file, line, _ := runtime.Caller(1)
		if fn := runtime.FuncForPC(pc); fn != nil {
			name = fn.Name()
		}
		entry.Error(
			err.Error(),
			zap.String("func", name),
			zap.String("file", fmt.Sprintf("%s:%d", file, line)),
			zap.Int("line", line),
		)
	case zap.FatalLevel:
		entry.Fatal(err.Error())
	case zap.PanicLevel:
		entry.Panic(err.Error())
	}
}
