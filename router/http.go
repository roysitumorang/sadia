package router

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/goccy/go-json"
	"github.com/gofiber/contrib/fibersentry"
	"github.com/gofiber/contrib/fiberzap/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/monitor"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/gofiber/fiber/v2/middleware/rewrite"
	"github.com/joho/godotenv"
	"github.com/roysitumorang/sadia/config"
	_ "github.com/roysitumorang/sadia/docs"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	fiberSwagger "github.com/swaggo/fiber-swagger"
	"go.uber.org/zap"
)

const (
	DefaultPort uint16 = 8080
)

func (q *Service) HTTPServerMain(ctx context.Context) error {
	ctxt := "Router-HTTPServerMain"
	app := fiber.New(fiber.Config{
		JSONEncoder: json.Marshal,
		JSONDecoder: json.Unmarshal,
		ErrorHandler: func(ctx *fiber.Ctx, err error) error {
			statusCode := fiber.StatusInternalServerError
			var e *fiber.Error
			if errors.As(err, &e) {
				statusCode = e.Code
			}
			return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(ctx)
		},
	})
	app.Use(
		recover.New(recover.Config{
			EnableStackTrace: true,
		}),
		fiberzap.New(fiberzap.Config{
			Logger: helper.GetLogger(),
		}),
		requestid.New(),
		compress.New(),
		rewrite.New(rewrite.Config{
			Rules: map[string]string{},
		}),
		cors.New(),
	)
	if sentryEnabled := os.Getenv("SENTRY_ENABLED") == "1"; sentryEnabled {
		_ = sentry.Init(sentry.ClientOptions{
			Dsn: os.Getenv("SENTRY_DSN"),
			BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
				return event
			},
			Debug:            true,
			AttachStacktrace: true,
			EnableTracing:    true,
		})
		app.Use(fibersentry.New(fibersentry.Config{
			Repanic:         true,
			WaitForDelivery: true,
		}))
	}
	if helper.GetEnv() == "development" {
		app.Get("/swagger/*", fiberSwagger.WrapHandler)
	}
	app.Get("/ping", func(c *fiber.Ctx) error {
		return helper.NewResponse(fiber.StatusOK).
			SetData(map[string]interface{}{
				"version": config.Version,
				"commit":  config.Commit,
				"build":   config.Build,
				"upsince": config.Now.Format(time.RFC3339),
				"uptime":  time.Since(config.Now).String(),
			}).WriteResponse(c)
	})
	app.Use(middleware.BasicAuth()).
		Get("/metrics", monitor.New(monitor.Config{
			APIOnly: true,
		})).
		Get("/env", func(c *fiber.Ctx) error {
			envMap, err := godotenv.Read(".env")
			if err != nil {
				helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrRead")
				return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
			}
			envMap["GO_VERSION"] = runtime.Version()
			return helper.NewResponse(fiber.StatusOK).SetData(envMap).WriteResponse(c)
		})
	app.Use(func(c *fiber.Ctx) error {
		return helper.NewResponse(fiber.StatusNotFound).WriteResponse(c)
	})
	port := DefaultPort
	if envPort, ok := os.LookupEnv("PORT"); ok && envPort != "" {
		if portInt, _ := strconv.Atoi(envPort); portInt >= 0 && portInt <= math.MaxUint16 {
			port = uint16(portInt)
		}
	}
	listenerPort := fmt.Sprintf(":%d", port)
	err := app.Listen(listenerPort)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrListen")
	}
	return err
}
