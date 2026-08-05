package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rin721/certmate/internal/app"
	"github.com/rin721/certmate/internal/config"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := healthcheck(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "配置错误:", err)
		os.Exit(1)
	}
	cfg.BuildVersion = version
	logger := newLogger(cfg.LogLevel)
	logger.Info("application initialized", "version", version, "environment", cfg.Environment)
	if cfg.PlaintextPassword && cfg.Environment == "production" {
		logger.Warn("生产模式正在使用明文管理员密码配置，建议改用 ADMIN_PASSWORD_HASH 或 Secret 文件")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	application, err := app.New(ctx, cfg, logger)
	if err != nil {
		logger.Error("application initialization failed", "error", err)
		os.Exit(1)
	}
	if err := application.Run(ctx); err != nil {
		logger.Error("application stopped unexpectedly", "error", err)
		os.Exit(1)
	}
}

func newLogger(level string) *slog.Logger {
	var parsed slog.Level
	if err := parsed.UnmarshalText([]byte(strings.ToUpper(level))); err != nil {
		parsed = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parsed}))
}

func healthcheck() error {
	address := strings.TrimSpace(os.Getenv("LISTEN_ADDR"))
	if address == "" || strings.HasPrefix(address, ":") {
		address = "127.0.0.1" + envOr(address, ":8080")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %s", resp.Status)
	}
	var payload struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if payload.Status != "ok" {
		return fmt.Errorf("unexpected health status %q", payload.Status)
	}
	return nil
}

func envOr(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
