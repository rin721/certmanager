package httpapi

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rin721/certmate/internal/audit"
	"github.com/rin721/certmate/internal/auth"
	"github.com/rin721/certmate/internal/certificate"
	"github.com/rin721/certmate/internal/jobs"
)

var allowedJobStatuses = map[string]bool{
	"pending": true, "running": true, "succeeded": true, "failed": true, "interrupted": true, "cancelled": true,
}

var allowedJobTypes = map[string]bool{
	"issue": true, "renew": true, "force_renew": true, "revoke": true, "self_signed_generate": true,
}

func (rt *Router) listJobs(w http.ResponseWriter, r *http.Request) {
	query := jobs.Query{
		CertificateID: strings.TrimSpace(r.URL.Query().Get("certificate_id")),
		Status:        strings.TrimSpace(r.URL.Query().Get("status")),
		JobType:       strings.TrimSpace(r.URL.Query().Get("job_type")),
	}
	if query.Status != "" && !allowedJobStatuses[query.Status] {
		writeError(w, http.StatusBadRequest, "JOB_FILTER_INVALID", "任务状态筛选无效")
		return
	}
	if query.JobType != "" && !allowedJobTypes[query.JobType] {
		writeError(w, http.StatusBadRequest, "JOB_FILTER_INVALID", "任务类型筛选无效")
		return
	}
	var err error
	query.Since, err = parseSince(r.URL.Query().Get("since"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "JOB_FILTER_INVALID", "任务时间筛选无效")
		return
	}
	query.Limit = parseLimit(r.URL.Query().Get("limit"))
	values, err := rt.records.Jobs(r.Context(), query)
	if err != nil {
		rt.internalError(w, r, "list jobs", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": values})
}

func (rt *Router) getJob(w http.ResponseWriter, r *http.Request) {
	value, err := rt.records.Job(r.Context(), strings.TrimSpace(chi.URLParam(r, "id")))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "JOB_NOT_FOUND", "任务不存在")
		return
	}
	if err != nil {
		rt.internalError(w, r, "get job", err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (rt *Router) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	query := audit.Query{
		CertificateID: strings.TrimSpace(r.URL.Query().Get("certificate_id")),
		EventType:     strings.TrimSpace(r.URL.Query().Get("event_type")),
		Limit:         parseLimit(r.URL.Query().Get("limit")),
	}
	var err error
	query.Since, err = parseSince(r.URL.Query().Get("since"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "AUDIT_FILTER_INVALID", "审计时间筛选无效")
		return
	}
	values, err := rt.records.AuditEvents(r.Context(), query)
	if err != nil {
		rt.internalError(w, r, "list audit events", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": values})
}

func (rt *Router) dashboard(w http.ResponseWriter, r *http.Request) {
	certificates, err := rt.certificates.List(r.Context())
	if err != nil {
		rt.internalError(w, r, "load dashboard certificates", err)
		return
	}
	now := time.Now().UTC()
	counts := map[string]int{"total": len(certificates), "active": 0, "expiring": 0, "expired": 0, "failed": 0}
	expiring := make([]certificate.Certificate, 0, 5)
	for _, value := range certificates {
		switch {
		case value.Status == certificate.StatusFailed:
			counts["failed"]++
		case value.NotAfter != nil && !value.NotAfter.After(now):
			counts["expired"]++
		case value.NotAfter != nil && value.NotAfter.Before(now.Add(30*24*time.Hour)):
			counts["expiring"]++
			if len(expiring) < 5 {
				expiring = append(expiring, value)
			}
		case value.Status == certificate.StatusActive:
			counts["active"]++
		}
	}
	recentJobs, err := rt.records.Jobs(r.Context(), jobs.Query{Limit: 5})
	if err != nil {
		rt.internalError(w, r, "load dashboard jobs", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"counts": counts, "recent_jobs": recentJobs, "expiring_certificates": expiring})
}

func (rt *Router) getSystemInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, rt.systemInfo.Get(r.Context()))
}

func (rt *Router) auditAdminEvent(r *http.Request, eventType, fallbackActor, result string, detail map[string]any) {
	if rt.records == nil {
		return
	}
	actor, ok := rt.auth.CurrentUser(r)
	if !ok {
		actor = fallbackActor
	}
	if actor == "" {
		actor = "unknown"
	}
	if err := rt.records.CreateAuditEvent(r.Context(), &audit.Event{
		EventType: eventType,
		Actor:     actor,
		ClientIP:  auth.ClientIP(r, rt.config.TrustsProxy(r.RemoteAddr)),
		Result:    result,
		Detail:    detail,
	}); err != nil {
		rt.logger.ErrorContext(r.Context(), "create audit event", "event_type", eventType, "error", err)
	}
}

func parseSince(raw string) (*time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func parseLimit(raw string) int {
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > 200 {
		return 100
	}
	return value
}
