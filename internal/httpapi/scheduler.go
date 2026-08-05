package httpapi

import (
	"errors"
	"net/http"

	"github.com/rin721/certmate/internal/scheduler"
)

func (rt *Router) getRenewalPolicy(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"policy": rt.scheduler.Policy(), "status": rt.scheduler.Status()})
}

func (rt *Router) updateRenewalPolicy(w http.ResponseWriter, r *http.Request) {
	var policy scheduler.Policy
	if err := decodeJSON(w, r, &policy, maxCertificateBody); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "请求格式无效")
		return
	}
	if err := rt.scheduler.Update(r.Context(), policy); err != nil {
		rt.auditAdminEvent(r, "renewal_policy.update", "admin", "failed", nil)
		if errors.Is(err, scheduler.ErrInvalidPolicy) {
			writeError(w, http.StatusBadRequest, "SCHEDULE_INVALID", "续签策略无效，旧策略继续运行")
			return
		}
		rt.internalError(w, r, "update renewal policy", err)
		return
	}
	rt.auditAdminEvent(r, "renewal_policy.update", "admin", "succeeded", map[string]any{"enabled": policy.Enabled, "cron_expression": policy.CronExpression, "timezone": policy.Timezone})
	writeJSON(w, http.StatusOK, map[string]any{"policy": rt.scheduler.Policy(), "status": rt.scheduler.Status()})
}

func (rt *Router) runRenewalNow(w http.ResponseWriter, r *http.Request) {
	if !rt.scheduler.RunNow() {
		rt.auditAdminEvent(r, "renewal_scan.run_now", "admin", "rejected", nil)
		writeError(w, http.StatusConflict, "SCHEDULE_RUN_ACTIVE", "续签扫描已在运行")
		return
	}
	rt.auditAdminEvent(r, "renewal_scan.run_now", "admin", "succeeded", nil)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}
