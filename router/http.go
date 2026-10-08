package router

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/coregx/coregex"
	"github.com/dustin/go-humanize"
	"github.com/getsentry/sentry-go"
	"github.com/goccy/go-json"
	"github.com/gofiber/contrib/v3/monitor"
	fibersentry "github.com/gofiber/contrib/v3/sentry"
	"github.com/gofiber/contrib/v3/swaggo"
	fiberzap "github.com/gofiber/contrib/v3/zap"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/compress"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/pprof"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/requestid"
	"github.com/gofiber/fiber/v3/middleware/rewrite"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/gofiber/template/jet/v3"
	"github.com/joho/godotenv"
	"github.com/roysitumorang/sadia/config"
	"github.com/roysitumorang/sadia/controllers"
	_ "github.com/roysitumorang/sadia/docs"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	"go.uber.org/zap"
)

const (
	DefaultPort uint16 = 8080
)

func (q *Service) HTTPServerMain(ctx context.Context) error {
	ctxt := "Router-HTTPServerMain"
	debug := helper.GetEnv() == "development"
	// Create a new engine
	engine := jet.New("./views", ".jet")
	engine.Debug(debug)
	engine.AddFunc("Comma", func(v int64) string {
		return humanize.Comma(v)
	})
	engine.AddFunc("HasPrefix", func(s, prefix string) bool {
		return strings.HasPrefix(s, prefix)
	})
	sessionMiddleware, sessionStore := session.NewWithStore(session.Config{
		Storage: q.Storage,
	})
	sessionStore.RegisterType(&models.User{})
	sessionStore.RegisterType(&models.Company{})
	sessionStore.RegisterType(&models.Session{})
	sessionStore.RegisterType(&models.Transaction{})
	sessionStore.RegisterType(&helper.FlashMessage{})
	app := fiber.New(fiber.Config{
		RegexHandler: coregex.MustCompile,
		JSONEncoder:  json.Marshal,
		JSONDecoder:  json.Unmarshal,
		Views:        engine,
		ErrorHandler: func(ctx fiber.Ctx, err error) error {
			statusCode := fiber.StatusInternalServerError
			if e, ok := errors.AsType[*fiber.Error](err); ok {
				statusCode = e.Code
			}
			return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(ctx)
		},
	})
	middlewares := []any{
		recover.New(recover.Config{
			EnableStackTrace: true,
		}),
		fiberzap.New(fiberzap.Config{
			Logger: helper.GetLogger(),
		}),
		requestid.New(requestid.Config{
			Next:      nil,
			Header:    fiber.HeaderXRequestID,
			Generator: helper.GenerateUniqueID,
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
				"/":                   "/account/me",
			},
		}),
		cors.New(),
		pprof.New(),
		sessionMiddleware,
	}
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
		middlewares = append(
			middlewares,
			fibersentry.New(fibersentry.Config{
				Repanic:         true,
				WaitForDelivery: true,
			}),
		)
	}
	app.Use(middlewares...)
	basicAuth := middleware.BasicAuth()
	if debug {
		app.Get("/swagger/*", swaggo.HandlerDefault)
	}
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
	controllers.NewJwtController(q.JwtService, q.AccountService).Mount(app.Group("/jwt"))
	controllers.NewAccountController(q.JwtService, q.AccountService, q.CompanyService, q.SessionService).Mount(app.Group("/account"))
	controllers.NewCompanyController(q.JwtService, q.AccountService, q.CompanyService, q.SessionService).Mount(app.Group("/company"))
	controllers.NewLogController(q.JwtService, q.AccountService, q.CompanyService, q.SessionService, q.LogService).Mount(app.Group("/log"))
	controllers.NewProductCategoryController(q.JwtService, q.AccountService, q.CompanyService, q.SessionService, q.ProductCategoryService, q.LogService).Mount(app.Group("/product_category"))
	controllers.NewProductController(q.JwtService, q.AccountService, q.CompanyService, q.SessionService, q.ProductCategoryService, q.ProductService, q.LogService).Mount(app.Group("/product"))
	controllers.NewSessionController(q.JwtService, q.AccountService, q.CompanyService, q.SessionService).Mount(app.Group("/session"))
	controllers.NewTransactionController(q.JwtService, q.AccountService, q.CompanyService, q.SessionService, q.ProductService, q.SequenceService, q.TransactionService).Mount(app.Group("/transaction"))
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
