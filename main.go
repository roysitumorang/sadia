//	@title			Sadia API
//	@version		0.1.0
//	@description	This is documentation of Sadia API.

//	@contact.name	Roy Situmorang
//	@contact.email	roy.situmorang@gmail.com

//	@host
//	@BasePath	/v1

//	@accept		json
//	@produce	json

//	@schemes	http https

//	@securitydefinitions.apikey	apiKey
//	@in							header
//	@name						x-api-key
//	@description				Sadia API call requires X-Api-Key request header

// @Security	ApiKeyAuth
package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/joho/godotenv"
	"github.com/robfig/cron/v3"
	"github.com/roysitumorang/sadia/config"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/router"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

func main() {
	ctxt := "Main"
	ctx := context.Background()
	helper.InitLogger()
	cmdVersion := &cobra.Command{
		Use:   "version",
		Short: "print version",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("Version: %s\nCommit: %s\nBuild: %s\n", config.Version, config.Commit, config.Build)
		},
	}
	cmdRun := &cobra.Command{
		Use:   "run",
		Short: "run app",
		Run: func(_ *cobra.Command, _ []string) {
			if err := godotenv.Load(".env"); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrLoad")
				return
			}
			if err := helper.InitHelper(); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrInitHelper")
				return
			}
			service, err := router.MakeHandler(ctx)
			if err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrMakeHandler")
				return
			}
			if err := service.Migration.Migrate(ctx); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrMigrate")
				return
			}
			var g errgroup.Group
			g.Go(func() error {
				return service.HTTPServerMain(ctx)
			})
			g.Go(func() error {
				c := cron.New(cron.WithChain(
					cron.Recover(cron.DefaultLogger),
				))
				// run every minute
				entryID, err := c.AddFunc("* * * * *", func() {
					rowsAffected, err := service.JwtUseCase.DeleteExpiredJWTs(ctx)
					if err != nil {
						helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDeleteExpiredJWTs")
						return
					}
					if rowsAffected > 0 {
						helper.Log(ctx, zap.InfoLevel, fmt.Sprintf("%d expired JWTs deleted", rowsAffected), ctxt, "")
					}
				})
				if err != nil {
					helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrAddFunc")
					return err
				}
				helper.Log(ctx, zap.InfoLevel, fmt.Sprintf("cron: entry added with ID %d", entryID), ctxt, "")
				c.Start()
				helper.Log(ctx, zap.InfoLevel, "cron: scheduled tasks running!...", ctxt, "")
				return nil
			})
			if err := g.Wait(); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrWait")
			}
		},
	}
	cmdMigration := &cobra.Command{
		Use:   "migration",
		Short: "new/run migration",
		Args: func(_ *cobra.Command, args []string) (err error) {
			if len(args) == 0 {
				err = errors.New("requires at least 1 arg (new|run")
				return
			}
			if args[0] != "new" && args[0] != "run" {
				err = fmt.Errorf("invalid first flag specified: %s", args[0])
			}
			return
		},
		Run: func(_ *cobra.Command, args []string) {
			now := time.Now()
			if err := godotenv.Load(".env"); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrLoad")
				return
			}
			if err := helper.InitHelper(); err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrInitHelper")
				return
			}
			service, err := router.MakeHandler(ctx)
			if err != nil {
				helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrMakeHandler")
				return
			}
			var activity string
			switch args[0] {
			case "new":
				if err := service.Migration.CreateMigrationFile(ctx); err != nil {
					helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrCreateMigrationFile")
					return
				}
				activity = "creating"
			case "run":
				if err := service.Migration.Migrate(ctx); err != nil {
					helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrMigrate")
					return
				}
				activity = "running"
			}
			duration := time.Since(now)
			helper.Log(ctx, zap.InfoLevel, fmt.Sprintf("%s migration successfully in %s", activity, duration.String()), ctxt, "")
		},
	}
	rootCmd := &cobra.Command{Use: config.AppName}
	rootCmd.AddCommand(
		cmdVersion,
		cmdRun,
		cmdMigration,
	)
	rootCmd.SuggestionsMinimumDistance = 1
	if err := rootCmd.Execute(); err != nil {
		helper.Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrExecute")
	}
}
