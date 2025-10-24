package router

import (
	"context"
	"encoding/gob"
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
	"github.com/gofiber/contrib/monitor"
	"github.com/gofiber/fiber/v2/utils"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/compress"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/requestid"
	"github.com/gofiber/fiber/v3/middleware/rewrite"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/gofiber/template/jet/v2"
	"github.com/joho/godotenv"
	"github.com/roysitumorang/sadia/config"
	_ "github.com/roysitumorang/sadia/docs"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	accountPresenter "github.com/roysitumorang/sadia/modules/account/presenter"
	companyPresenter "github.com/roysitumorang/sadia/modules/company/presenter"
	jwtPresenter "github.com/roysitumorang/sadia/modules/jwt/presenter"
	productPresenter "github.com/roysitumorang/sadia/modules/product/presenter"
	productCategoryPresenter "github.com/roysitumorang/sadia/modules/product_category/presenter"
	sessionPresenter "github.com/roysitumorang/sadia/modules/session/presenter"
	storePresenter "github.com/roysitumorang/sadia/modules/store/presenter"
	transactionPresenter "github.com/roysitumorang/sadia/modules/transaction/presenter"
	fiberSwagger "github.com/swaggo/fiber-swagger"
	"go.uber.org/zap"
)

const (
	DefaultPort uint16 = 8080
)

func (q *Service) HTTPServerMain(ctx context.Context) error {
	ctxt := "Router-HTTPServerMain"
	// Create a new engine
	engine := jet.New("./views", ".jet")
	sessionStore := session.New(session.Config{
		Storage: q.Storage,
	})
	gob.Register(map[string]any{})
	app := fiber.New(fiber.Config{
		JSONEncoder: json.Marshal,
		JSONDecoder: json.Unmarshal,
		Views:       engine,
		ErrorHandler: func(ctx fiber.Ctx, err error) error {
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
		logger.New(logger.Config{
			Format:     logger.JSONFormat,
			TimeFormat: time.RFC3339,
		}),
		requestid.New(requestid.Config{
			Next:      nil,
			Header:    fiber.HeaderXRequestID,
			Generator: utils.UUIDv4,
		}),
		compress.New(),
		rewrite.New(rewrite.Config{
			Rules: map[string]string{
				"/v1/admin/account":   "/v1/account/admin",
				"/v1/admin/account/*": "/v1/account/admin/$1",
				"/v1/admin/jwt":       "/v1/jwt/admin",
				"/v1/admin/jwt/*":     "/v1/jwt/admin/$1",
				"/v1/admin/company":   "/v1/company/admin",
				"/v1/admin/company/*": "/v1/company/admin/$1",
			},
		}),
		cors.New(),
		sessionStore,
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
	basicAuth := middleware.BasicAuth()
	_ = fiberSwagger.WrapHandler
	// if helper.GetEnv() == "development" {
	// 	app.Get("/swagger/*", fiberSwagger.WrapHandler)
	// }
	app.Get("/ping", func(c fiber.Ctx) error {
		return helper.NewResponse(fiber.StatusOK).
			SetData(map[string]any{
				"version": config.Version,
				"commit":  config.Commit,
				"build":   config.Build,
				"upsince": config.Now.Format(time.RFC3339),
				"uptime":  time.Since(config.Now).String(),
			}).WriteResponse(c)
	}).
		Get("/metrics", basicAuth, monitor.New(monitor.Config{
			APIOnly: true,
		})).
		Get("/env", basicAuth, func(c fiber.Ctx) error {
			envMap, err := godotenv.Read(".env")
			if err != nil {
				helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrRead")
				return helper.NewResponse(fiber.StatusBadRequest).SetMessage(err.Error()).WriteResponse(c)
			}
			envMap["GO_VERSION"] = runtime.Version()
			return helper.NewResponse(fiber.StatusOK).SetData(envMap).WriteResponse(c)
		})
	jwtPresenter.New(q.JwtUseCase, q.AccountUseCase).Mount(app.Group("/jwt"))
	accountPresenter.New(q.JwtUseCase, q.AccountUseCase).Mount(app.Group("/account"))
	companyPresenter.New(q.JwtUseCase, q.AccountUseCase, q.CompanyUseCase).Mount(app.Group("/company"))
	productCategoryPresenter.New(q.JwtUseCase, q.AccountUseCase, q.ProductCategoryUseCase).Mount(app.Group("/product_category"))
	productPresenter.New(q.JwtUseCase, q.AccountUseCase, q.ProductCategoryUseCase, q.ProductUseCase).Mount(app.Group("/product"))
	storePresenter.New(q.JwtUseCase, q.AccountUseCase, q.StoreUseCase).Mount(app.Group("/store"))
	sessionPresenter.New(q.JwtUseCase, q.AccountUseCase, q.StoreUseCase, q.SessionUseCase).Mount(app.Group("/session"))
	transactionPresenter.New(q.JwtUseCase, q.AccountUseCase, q.SessionUseCase, q.ProductUseCase, q.SequenceUseCase, q.TransactionUseCase).Mount(app.Group("/transaction"))
	app.Use(func(c fiber.Ctx) error {
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
