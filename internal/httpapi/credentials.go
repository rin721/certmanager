package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rin721/certmate/internal/credential"
)

func (rt *Router) listDNSProviders(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": rt.credentials.Providers()})
}

func (rt *Router) listDNSCredentials(w http.ResponseWriter, r *http.Request) {
	values, err := rt.credentials.List(r.Context())
	if err != nil {
		rt.internalError(w, r, "list DNS credentials", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": values})
}

func (rt *Router) createDNSCredential(w http.ResponseWriter, r *http.Request) {
	var request credential.CreateRequest
	if err := decodeJSON(w, r, &request, maxCertificateBody); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "请求格式无效")
		return
	}
	value, err := rt.credentials.Create(r.Context(), request)
	request.Values = nil
	if err != nil {
		rt.auditAdminEvent(r, "dns_credential.create", "admin", "failed", map[string]any{"provider": request.Provider})
		writeError(w, http.StatusBadRequest, "DNS_CREDENTIAL_INVALID", "DNS 凭据配置无效")
		return
	}
	rt.auditAdminEvent(r, "dns_credential.create", "admin", "succeeded", map[string]any{"credential_id": value.ID, "provider": value.Provider})
	writeJSON(w, http.StatusCreated, value)
}

func (rt *Router) updateDNSCredential(w http.ResponseWriter, r *http.Request) {
	var request credential.CreateRequest
	if err := decodeJSON(w, r, &request, maxCertificateBody); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "请求格式无效")
		return
	}
	id := chi.URLParam(r, "id")
	var value credential.Credential
	var err error
	if request.Provider == "" {
		value, err = rt.credentials.Rename(r.Context(), id, request.Name)
	} else {
		value, err = rt.credentials.Update(r.Context(), id, request)
	}
	request.Values = nil
	if errors.Is(err, credential.ErrNotFound) {
		writeError(w, http.StatusNotFound, "DNS_CREDENTIAL_NOT_FOUND", "DNS 凭据不存在")
		return
	}
	if err != nil {
		rt.auditAdminEvent(r, "dns_credential.update", "admin", "failed", map[string]any{"credential_id": id})
		writeError(w, http.StatusBadRequest, "DNS_CREDENTIAL_INVALID", "DNS 凭据配置无效")
		return
	}
	rt.auditAdminEvent(r, "dns_credential.update", "admin", "succeeded", map[string]any{"credential_id": id, "provider": value.Provider})
	writeJSON(w, http.StatusOK, value)
}

func (rt *Router) testDNSCredential(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := rt.credentials.Test(r.Context(), id)
	if errors.Is(err, credential.ErrNotFound) {
		writeError(w, http.StatusNotFound, "DNS_CREDENTIAL_NOT_FOUND", "DNS 凭据不存在")
		return
	}
	if err != nil {
		rt.auditAdminEvent(r, "dns_credential.test", "admin", "failed", map[string]any{"credential_id": id})
		writeError(w, http.StatusBadRequest, "DNS_CREDENTIAL_TEST_FAILED", "凭据无法解析，请检查密文或环境变量引用")
		return
	}
	rt.auditAdminEvent(r, "dns_credential.test", "admin", "succeeded", map[string]any{"credential_id": id})
	writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

func (rt *Router) dnsCredentialReferences(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := rt.credentials.Get(r.Context(), id); errors.Is(err, credential.ErrNotFound) {
		writeError(w, http.StatusNotFound, "DNS_CREDENTIAL_NOT_FOUND", "DNS 凭据不存在")
		return
	} else if err != nil {
		rt.internalError(w, r, "get DNS credential", err)
		return
	}
	values, err := rt.certificates.List(r.Context())
	if err != nil {
		rt.internalError(w, r, "list DNS credential references", err)
		return
	}
	items := make([]map[string]any, 0)
	for _, value := range values {
		if value.DNSCredentialID == id {
			items = append(items, map[string]any{"id": value.ID, "name": value.Name, "primary_domain": value.PrimaryDomain, "status": value.Status})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (rt *Router) deleteDNSCredential(w http.ResponseWriter, r *http.Request) {
	err := rt.credentials.Delete(r.Context(), chi.URLParam(r, "id"))
	if errors.Is(err, credential.ErrNotFound) {
		writeError(w, http.StatusNotFound, "DNS_CREDENTIAL_NOT_FOUND", "DNS 凭据不存在")
		return
	}
	if err != nil {
		rt.internalError(w, r, "delete DNS credential", err)
		return
	}
	rt.auditAdminEvent(r, "dns_credential.delete", "admin", "succeeded", map[string]any{"credential_id": chi.URLParam(r, "id")})
	w.WriteHeader(http.StatusNoContent)
}
