package httpapi

import (
	"context"
	"crypto/sha256"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/csrf"
	"github.com/rin721/certmate/internal/audit"
	"github.com/rin721/certmate/internal/auth"
	"github.com/rin721/certmate/internal/certificate"
	"github.com/rin721/certmate/internal/config"
	"github.com/rin721/certmate/internal/credential"
	"github.com/rin721/certmate/internal/jobs"
	"github.com/rin721/certmate/internal/scheduler"
	"github.com/rin721/certmate/internal/systeminfo"
	"github.com/rin721/certmate/internal/webui"
)

type Router struct {
	config    config.Config
	logger    *slog.Logger
	started   time.Time
	auth      *auth.Manager
	readiness interface{ PingContext(context.Context) error }
	records   interface {
		Jobs(context.Context, jobs.Query) ([]jobs.Run, error)
		Job(context.Context, string) (jobs.Run, error)
		AuditEvents(context.Context, audit.Query) ([]audit.Event, error)
		CreateAuditEvent(context.Context, *audit.Event) error
	}
	certificates *certificate.Service
	credentials  *credential.Service
	scheduler    *scheduler.Controller
	systemInfo   *systeminfo.Service
}

func NewRouter(cfg config.Config, logger *slog.Logger, authManager *auth.Manager, readiness interface{ PingContext(context.Context) error }, certificates *certificate.Service, credentials *credential.Service, schedulerController *scheduler.Controller, systemInfo *systeminfo.Service) http.Handler {
	router := &Router{config: cfg, logger: logger, started: time.Now(), auth: authManager, readiness: readiness, certificates: certificates, credentials: credentials, scheduler: schedulerController, systemInfo: systemInfo}
	if records, ok := readiness.(interface {
		Jobs(context.Context, jobs.Query) ([]jobs.Run, error)
		Job(context.Context, string) (jobs.Run, error)
		AuditEvents(context.Context, audit.Query) ([]audit.Event, error)
		CreateAuditEvent(context.Context, *audit.Event) error
	}); ok {
		router.records = records
	}
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(router.securityHeaders)
	r.Use(router.accessLog)

	r.Get("/healthz", router.health)
	r.Get("/readyz", router.ready)
	r.Get("/.well-known/acme-challenge/{token}", router.acmeHTTPChallenge)
	r.Handle("/.well-known/acme-challenge/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/meta", router.meta)
		r.Route("/auth", func(r chi.Router) {
			r.Get("/csrf", router.csrfToken)
			r.Post("/login", router.login)
			r.Group(func(r chi.Router) {
				r.Use(router.requireAuth)
				r.Post("/logout", router.logout)
				r.Get("/me", router.me)
				r.Post("/reauthenticate", router.reauthenticate)
			})
		})
		if router.certificates != nil {
			r.Group(func(r chi.Router) {
				r.Use(router.requireAuth)
				r.Get("/certificates", router.listCertificates)
				r.Post("/certificates", router.createCertificate)
				r.Get("/certificates/{id}", router.getCertificate)
				r.Patch("/certificates/{id}", router.updateCertificate)
				r.Delete("/certificates/{id}", router.deleteCertificate)
				r.Post("/certificates/{id}/renew", router.renewCertificate)
				r.Post("/certificates/{id}/force-renew", router.forceRenewCertificate)
				r.Post("/certificates/{id}/revoke", router.revokeCertificate)
				r.Get("/certificates/{id}/files", router.listCertificateFiles)
				r.Get("/certificates/{id}/files/{type}", router.viewCertificateFile)
				r.Get("/certificates/{id}/files/{type}/download", router.downloadCertificateFile)
				r.Post("/certificates/{id}/files/archive", router.downloadCertificateArchive)
				r.Post("/certificates/{id}/files/private-key/reveal", router.revealPrivateKey)
				r.Post("/certificates/{id}/files/private-key/copy-audit", router.auditPrivateKeyCopy)
			})
		}
		if router.records != nil {
			r.Group(func(r chi.Router) {
				r.Use(router.requireAuth)
				r.Get("/dashboard", router.dashboard)
				r.Get("/jobs", router.listJobs)
				r.Get("/jobs/{id}", router.getJob)
				r.Get("/audit-events", router.listAuditEvents)
			})
		}
		if router.systemInfo != nil {
			r.With(router.requireAuth).Get("/system/info", router.getSystemInfo)
		}
		if router.credentials != nil {
			r.Group(func(r chi.Router) {
				r.Use(router.requireAuth)
				r.Get("/dns-providers", router.listDNSProviders)
				r.Get("/dns-credentials", router.listDNSCredentials)
				r.Post("/dns-credentials", router.createDNSCredential)
				r.Patch("/dns-credentials/{id}", router.updateDNSCredential)
				r.Post("/dns-credentials/{id}/test", router.testDNSCredential)
				r.Get("/dns-credentials/{id}/references", router.dnsCredentialReferences)
				r.Delete("/dns-credentials/{id}", router.deleteDNSCredential)
			})
		}
		if router.scheduler != nil {
			r.Group(func(r chi.Router) {
				r.Use(router.requireAuth)
				r.Get("/renewal-policy", router.getRenewalPolicy)
				r.Put("/renewal-policy", router.updateRenewalPolicy)
				r.Post("/renewal-policy/run-now", router.runRenewalNow)
			})
		}
		r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "接口不存在")
		})
	})
	r.Handle("/*", router.spaHandler())
	csrfKey := sha256.Sum256(append([]byte("certmate/csrf/v1:"), cfg.SessionSecret...))
	protected := csrf.Protect(
		csrfKey[:],
		csrf.Path("/"),
		csrf.HttpOnly(true),
		csrf.SameSite(csrf.SameSiteStrictMode),
		csrf.Secure(cfg.SessionCookieSecure),
		csrf.ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			router.logger.WarnContext(r.Context(), "csrf validation failed", "reason", csrf.FailureReason(r))
			writeError(w, http.StatusForbidden, "CSRF_INVALID", "CSRF 校验失败")
		})),
	)(r)
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !requestIsHTTPS(request, cfg.TrustsProxy(request.RemoteAddr)) {
			request = csrf.PlaintextHTTPRequest(request)
		}
		protected.ServeHTTP(w, request)
	})
}

func requestIsHTTPS(r *http.Request, trustForwardedHeaders bool) bool {
	if r.TLS != nil {
		return true
	}
	return trustForwardedHeaders && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func (rt *Router) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (rt *Router) ready(w http.ResponseWriter, _ *http.Request) {
	if rt.readiness != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := rt.readiness.PingContext(ctx); err != nil {
			writeError(w, http.StatusServiceUnavailable, "NOT_READY", "数据库暂时不可用")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (rt *Router) meta(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"app_name":           rt.config.AppName,
		"environment":        rt.config.Environment,
		"enable_acme":        rt.config.EnableACME,
		"enable_self_signed": rt.config.EnableSelfSigned,
	})
}

func (rt *Router) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func (rt *Router) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		rt.logger.InfoContext(r.Context(), "http request",
			"request_id", middleware.GetReqID(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

func (rt *Router) spaHandler() http.Handler {
	dist, err := fs.Sub(webui.Assets, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "请求方法不允许")
			return
		}
		clean := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if clean != "." && clean != "" {
			if info, statErr := fs.Stat(dist, clean); statErr == nil && !info.IsDir() {
				files.ServeHTTP(w, r)
				return
			}
		}
		r.URL.Path = "/"
		files.ServeHTTP(w, r)
	})
}
