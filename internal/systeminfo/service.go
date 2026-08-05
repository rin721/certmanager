// Package systeminfo 汇总不含 Secret 的运行时诊断信息。
package systeminfo

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/rin721/certmate/internal/config"
	"github.com/rin721/certmate/internal/scheduler"
)

const maxVersionOutput = 8 << 10

type Readiness interface {
	PingContext(context.Context) error
}

type Service struct {
	config    config.Config
	store     Readiness
	scheduler *scheduler.Controller
}

type Info struct {
	ApplicationVersion string           `json:"application_version"`
	GoVersion          string           `json:"go_version"`
	ACMEShVersion      string           `json:"acme_sh_version"`
	OpenSSLVersion     string           `json:"openssl_version"`
	SQLiteStatus       string           `json:"sqlite_status"`
	DataDirectory      string           `json:"data_directory"`
	CertificateDir     string           `json:"certificate_directory"`
	Timezone           string           `json:"timezone"`
	Scheduler          scheduler.Status `json:"scheduler"`
}

func New(cfg config.Config, store Readiness, controller *scheduler.Controller) *Service {
	return &Service{config: cfg, store: store, scheduler: controller}
}

func (s *Service) Get(ctx context.Context) Info {
	databaseStatus := "ok"
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	if err := s.store.PingContext(pingCtx); err != nil {
		databaseStatus = "unavailable"
	}
	cancel()
	return Info{
		ApplicationVersion: valueOr(s.config.BuildVersion, "dev"),
		GoVersion:          runtime.Version(),
		ACMEShVersion:      commandVersion(ctx, s.config.ACMEShBinary, "--version"),
		OpenSSLVersion:     commandVersion(ctx, s.config.OpenSSLBinary, "version"),
		SQLiteStatus:       databaseStatus,
		DataDirectory:      s.config.DataDir,
		CertificateDir:     s.config.CertOutputDir,
		Timezone:           s.config.Timezone,
		Scheduler:          s.scheduler.Status(),
	}
}

func commandVersion(parent context.Context, binary string, argument string) string {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	buffer := &limitedBuffer{remaining: maxVersionOutput}
	command := exec.CommandContext(ctx, binary, argument)
	command.Stdout, command.Stderr = buffer, buffer
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	if err := command.Run(); err != nil {
		return "unavailable"
	}
	line, _, _ := strings.Cut(strings.TrimSpace(buffer.String()), "\n")
	return valueOr(strings.TrimSpace(line), "unavailable")
}

type limitedBuffer struct {
	bytes.Buffer
	remaining int
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	if b.remaining <= 0 {
		return original, nil
	}
	if len(value) > b.remaining {
		value = value[:b.remaining]
	}
	written, err := b.Buffer.Write(value)
	b.remaining -= written
	if err != nil && !errors.Is(err, context.Canceled) {
		return written, err
	}
	return original, nil
}

func valueOr(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
