// Package app 组装并管理单体进程的生命周期。
package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rin721/certmate/internal/auth"
	"github.com/rin721/certmate/internal/certificate"
	"github.com/rin721/certmate/internal/certificate/acmesh"
	certfiles "github.com/rin721/certmate/internal/certificate/files"
	"github.com/rin721/certmate/internal/certificate/selfsigned"
	"github.com/rin721/certmate/internal/config"
	"github.com/rin721/certmate/internal/credential"
	"github.com/rin721/certmate/internal/httpapi"
	"github.com/rin721/certmate/internal/scheduler"
	"github.com/rin721/certmate/internal/store/sqlite"
	"github.com/rin721/certmate/internal/systeminfo"
)

type App struct {
	config    config.Config
	logger    *slog.Logger
	server    *http.Server
	store     *sqlite.Store
	scheduler *scheduler.Controller
}

func New(ctx context.Context, cfg config.Config, logger *slog.Logger) (*App, error) {
	for _, directory := range []string{
		cfg.DataDir, cfg.CertOutputDir, cfg.ACMEHome, cfg.ACMEChallengeDir,
		filepath.Join(cfg.DataDir, "logs"), filepath.Join(cfg.DataDir, "temp"), filepath.Join(cfg.DataDir, "backups"),
	} {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			return nil, errors.New("创建应用数据目录失败")
		}
	}
	store, err := sqlite.Open(ctx, cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if err := store.Migrate(ctx); err != nil {
		store.Close()
		return nil, err
	}
	interrupted, err := store.MarkInterruptedJobs(ctx)
	if err != nil {
		store.Close()
		return nil, err
	}
	if interrupted > 0 {
		logger.Warn("recovered interrupted jobs", "count", interrupted)
	}
	var credentialService *credential.Service
	var acmeEngine acmesh.ACMEEngine
	if cfg.EnableACME {
		cipher, err := credential.NewCipher(cfg.AppEncryptionKey)
		if err != nil {
			store.Close()
			return nil, err
		}
		credentialService = credential.NewService(store, credential.NewRegistry(), cipher)
		acmeEngine = acmesh.NewCLI(cfg.ACMEShBinary, cfg.ACMEHome, cfg.ACMEChallengeDir, filepath.Join(cfg.DataDir, "temp"), 10*time.Minute)
	}
	certificateService := certificate.NewService(
		store,
		selfsigned.NewCLI(cfg.OpenSSLBinary, filepath.Join(cfg.DataDir, "temp"), cfg.CommandTimeout),
		certfiles.NewPublisher(cfg.CertOutputDir, filepath.Join(cfg.DataDir, "backups")),
		acmeEngine,
		credentialService,
	)
	schedulerController := scheduler.NewController(ctx, store, certificateService.RunRenewalScan, logger)
	if err := schedulerController.Start(ctx); err != nil {
		store.Close()
		return nil, err
	}
	application := &App{
		config:    cfg,
		logger:    logger,
		store:     store,
		scheduler: schedulerController,
		server: &http.Server{
			Addr:              cfg.ListenAddr,
			Handler:           httpapi.NewRouter(cfg, logger, auth.NewManager(cfg), store, certificateService, credentialService, schedulerController, systeminfo.New(cfg, store, schedulerController)),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       90 * time.Second,
			MaxHeaderBytes:    1 << 20,
		},
	}
	return application, nil
}

func (a *App) Run(ctx context.Context) error {
	defer func() {
		if err := a.store.Close(); err != nil {
			a.logger.Error("database close failed", "error", err)
		}
	}()
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := a.scheduler.Stop(stopCtx); err != nil {
			a.logger.Error("scheduler stop failed", "error", err)
		}
	}()
	errCh := make(chan error, 1)
	go func() {
		a.logger.Info("server starting", "app", a.config.AppName, "address", a.config.ListenAddr)
		errCh <- a.server.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), a.config.ShutdownTimeout)
		defer cancel()
		a.logger.Info("server stopping")
		return a.server.Shutdown(shutdownCtx)
	}
}
