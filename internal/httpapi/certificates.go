package httpapi

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rin721/certmate/internal/auth"
	"github.com/rin721/certmate/internal/certificate"
)

const maxCertificateBody = 64 << 10

var certificateFileNames = map[string]string{
	"cert": "cert.pem", "chain": "chain.pem", "fullchain": "fullchain.pem", "private-key": "privkey.pem",
}

type createCertificateRequest struct {
	Mode                string   `json:"mode"`
	Name                string   `json:"name"`
	PrimaryDomain       string   `json:"primary_domain"`
	SANs                []string `json:"sans"`
	KeyType             string   `json:"key_type"`
	ValidDays           int      `json:"valid_days"`
	OutputDirectory     string   `json:"output_directory"`
	AutoRenewEnabled    bool     `json:"auto_renew_enabled"`
	RenewBeforeDays     int      `json:"renew_before_days"`
	CreateRenewedMarker bool     `json:"create_renewed_marker"`
	ChallengeType       string   `json:"challenge_type"`
	DNSCredentialID     string   `json:"dns_credential_id"`
	CADirectoryURL      string   `json:"ca_directory_url"`
	ACMEEmail           string   `json:"acme_email"`
}

type deleteCertificateRequest struct {
	Password    string `json:"password"`
	ConfirmName string `json:"confirm_name"`
	DeleteFiles bool   `json:"delete_files"`
}

type archiveCertificateRequest struct {
	IncludePrivateKey bool   `json:"include_private_key"`
	Password          string `json:"password"`
}

func writeRedundantDomainError(w http.ResponseWriter, err error) bool {
	var redundantDomainError *certificate.RedundantDomainError
	if !errors.As(err, &redundantDomainError) {
		return false
	}
	writeError(w, http.StatusBadRequest, "CERT_DOMAIN_REDUNDANT", redundantDomainError.Error())
	return true
}

func (rt *Router) listCertificates(w http.ResponseWriter, r *http.Request) {
	values, err := rt.certificates.List(r.Context())
	if err != nil {
		rt.internalError(w, r, "list certificates", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": values})
}

func (rt *Router) createCertificate(w http.ResponseWriter, r *http.Request) {
	var request createCertificateRequest
	if err := decodeJSON(w, r, &request, maxCertificateBody); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "请求格式无效")
		return
	}
	actor, _ := rt.auth.CurrentUser(r)
	clientIP := auth.ClientIP(r, rt.config.TrustsProxy(r.RemoteAddr))
	var value certificate.Certificate
	var err error
	switch certificate.Mode(request.Mode) {
	case certificate.ModeSelfSigned:
		value, err = rt.certificates.CreateSelfSigned(r.Context(), certificate.CreateSelfSignedRequest{
			Name: request.Name, PrimaryDomain: request.PrimaryDomain, SANs: request.SANs,
			KeyType: request.KeyType, ValidDays: request.ValidDays, OutputDirectory: request.OutputDirectory,
			AutoRenewEnabled: request.AutoRenewEnabled, RenewBeforeDays: request.RenewBeforeDays,
			CreateRenewedMarker: request.CreateRenewedMarker,
		}, actor, clientIP)
	case certificate.ModeACME:
		value, err = rt.certificates.CreateACME(r.Context(), certificate.CreateACMERequest{
			Name: request.Name, PrimaryDomain: request.PrimaryDomain, SANs: request.SANs,
			KeyType: request.KeyType, OutputDirectory: request.OutputDirectory,
			AutoRenewEnabled: request.AutoRenewEnabled, RenewBeforeDays: request.RenewBeforeDays,
			CreateRenewedMarker: request.CreateRenewedMarker, ChallengeType: request.ChallengeType,
			DNSCredentialID: request.DNSCredentialID, CADirectoryURL: request.CADirectoryURL, ACMEEmail: request.ACMEEmail,
		}, actor, clientIP)
	default:
		writeError(w, http.StatusBadRequest, "CERT_MODE_UNSUPPORTED", "不支持的证书模式")
		return
	}
	if err != nil {
		rt.logger.WarnContext(r.Context(), "certificate creation failed", "error", err)
		if writeRedundantDomainError(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, "CERT_ISSUE_FAILED", "证书创建失败，请检查配置和任务日志")
		return
	}
	writeJSON(w, http.StatusCreated, value)
}

func (rt *Router) getCertificate(w http.ResponseWriter, r *http.Request) {
	value, ok := rt.certificateByID(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (rt *Router) updateCertificate(w http.ResponseWriter, r *http.Request) {
	var request certificate.UpdateRequest
	if err := decodeJSON(w, r, &request, maxCertificateBody); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "请求格式无效")
		return
	}
	actor, _ := rt.auth.CurrentUser(r)
	value, err := rt.certificates.Update(r.Context(), chi.URLParam(r, "id"), request, actor, auth.ClientIP(r, rt.config.TrustsProxy(r.RemoteAddr)))
	if errors.Is(err, certificate.ErrNotFound) {
		writeError(w, http.StatusNotFound, "CERT_NOT_FOUND", "证书不存在")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "CERT_UPDATE_INVALID", "证书设置无效")
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (rt *Router) renewCertificate(w http.ResponseWriter, r *http.Request) {
	rt.runCertificateRenewal(w, r, false)
}

func (rt *Router) issueCertificate(w http.ResponseWriter, r *http.Request) {
	actor, _ := rt.auth.CurrentUser(r)
	value, err := rt.certificates.Issue(r.Context(), chi.URLParam(r, "id"), actor, auth.ClientIP(r, rt.config.TrustsProxy(r.RemoteAddr)))
	if errors.Is(err, certificate.ErrNotFound) {
		writeError(w, http.StatusNotFound, "CERT_NOT_FOUND", "证书不存在")
		return
	}
	if errors.Is(err, certificate.ErrOperationRunning) {
		writeError(w, http.StatusConflict, "CERT_OPERATION_RUNNING", "该证书已有任务正在运行")
		return
	}
	if err != nil {
		if writeRedundantDomainError(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, "CERT_ISSUE_FAILED", "证书重新签发失败，请查看任务日志")
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (rt *Router) forceRenewCertificate(w http.ResponseWriter, r *http.Request) {
	if !rt.auth.Reauthenticated(r) {
		writeError(w, http.StatusForbidden, "AUTH_REAUTH_REQUIRED", "强制续签前必须重新认证")
		return
	}
	rt.runCertificateRenewal(w, r, true)
}

func (rt *Router) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	var request passwordRequest
	if err := decodeJSON(w, r, &request, maxAuthBody); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "请求格式无效")
		return
	}
	if err := rt.auth.Reauthenticate(w, r, request.Password); err != nil {
		request.Password = ""
		writeError(w, http.StatusUnauthorized, "AUTH_REAUTH_REQUIRED", "撤销证书前必须重新认证")
		return
	}
	request.Password = ""
	actor, _ := rt.auth.CurrentUser(r)
	value, err := rt.certificates.Revoke(r.Context(), chi.URLParam(r, "id"), actor, auth.ClientIP(r, rt.config.TrustsProxy(r.RemoteAddr)))
	if errors.Is(err, certificate.ErrNotFound) {
		writeError(w, http.StatusNotFound, "CERT_NOT_FOUND", "证书不存在")
		return
	}
	if errors.Is(err, certificate.ErrOperationRunning) {
		writeError(w, http.StatusConflict, "CERT_OPERATION_RUNNING", "该证书已有任务正在运行")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "CERT_REVOKE_FAILED", "证书撤销失败，请查看任务日志")
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (rt *Router) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	var request deleteCertificateRequest
	if err := decodeJSON(w, r, &request, maxAuthBody); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "请求格式无效")
		return
	}
	value, ok := rt.certificateByID(w, r)
	if !ok {
		request.Password = ""
		return
	}
	if request.ConfirmName != value.Name {
		request.Password = ""
		writeError(w, http.StatusBadRequest, "CERT_DELETE_CONFIRMATION_INVALID", "证书名称确认不匹配")
		return
	}
	if err := rt.auth.Reauthenticate(w, r, request.Password); err != nil {
		request.Password = ""
		writeError(w, http.StatusUnauthorized, "AUTH_REAUTH_REQUIRED", "删除证书前必须重新认证")
		return
	}
	request.Password = ""
	actor, _ := rt.auth.CurrentUser(r)
	err := rt.certificates.Delete(r.Context(), value.ID, request.DeleteFiles, actor, auth.ClientIP(r, rt.config.TrustsProxy(r.RemoteAddr)))
	if errors.Is(err, certificate.ErrOperationRunning) {
		writeError(w, http.StatusConflict, "CERT_OPERATION_RUNNING", "该证书已有任务正在运行")
		return
	}
	if err != nil {
		rt.internalError(w, r, "delete certificate", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (rt *Router) runCertificateRenewal(w http.ResponseWriter, r *http.Request, force bool) {
	actor, _ := rt.auth.CurrentUser(r)
	value, err := rt.certificates.Renew(r.Context(), chi.URLParam(r, "id"), force, actor, auth.ClientIP(r, rt.config.TrustsProxy(r.RemoteAddr)))
	if errors.Is(err, certificate.ErrNotFound) {
		writeError(w, http.StatusNotFound, "CERT_NOT_FOUND", "证书不存在")
		return
	}
	if errors.Is(err, certificate.ErrOperationRunning) {
		writeError(w, http.StatusConflict, "CERT_OPERATION_RUNNING", "该证书已有任务正在运行")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "CERT_RENEW_FAILED", "证书续签失败，请查看任务日志")
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (rt *Router) listCertificateFiles(w http.ResponseWriter, r *http.Request) {
	value, ok := rt.certificateByID(w, r)
	if !ok {
		return
	}
	items := make([]map[string]any, 0, len(certificateFileNames))
	for fileType, filename := range certificateFileNames {
		items = append(items, map[string]any{
			"type": fileType, "filename": filename, "private": fileType == "private-key",
			"container_path": rt.certificates.ContainerPath(value, filename),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (rt *Router) viewCertificateFile(w http.ResponseWriter, r *http.Request) {
	fileType := chi.URLParam(r, "type")
	if fileType == "private-key" {
		writeError(w, http.StatusForbidden, "PRIVATE_KEY_ACCESS_DENIED", "私钥必须通过重新认证接口查看")
		return
	}
	rt.serveCertificateFile(w, r, false)
}

func (rt *Router) downloadCertificateFile(w http.ResponseWriter, r *http.Request) {
	if chi.URLParam(r, "type") == "private-key" && !rt.auth.Reauthenticated(r) {
		writeError(w, http.StatusForbidden, "AUTH_REAUTH_REQUIRED", "下载私钥前必须重新认证")
		return
	}
	rt.serveCertificateFile(w, r, true)
}

func (rt *Router) downloadCertificateArchive(w http.ResponseWriter, r *http.Request) {
	var request archiveCertificateRequest
	if err := decodeJSON(w, r, &request, maxAuthBody); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "请求格式无效")
		return
	}
	value, ok := rt.certificateByID(w, r)
	if !ok {
		request.Password = ""
		return
	}
	if request.IncludePrivateKey {
		if err := rt.auth.Reauthenticate(w, r, request.Password); err != nil {
			request.Password = ""
			writeError(w, http.StatusUnauthorized, "AUTH_REAUTH_REQUIRED", "下载包含私钥的压缩包前必须重新认证")
			return
		}
	}
	request.Password = ""
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	fileTypes := []string{"cert", "chain", "fullchain"}
	if request.IncludePrivateKey {
		fileTypes = append(fileTypes, "private-key")
	}
	for _, fileType := range fileTypes {
		filename := certificateFileNames[fileType]
		content, err := rt.certificates.ReadFile(r.Context(), value.ID, filename)
		if err != nil {
			_ = archive.Close()
			writeError(w, http.StatusNotFound, "CERT_FILE_NOT_FOUND", "证书文件不完整，无法创建压缩包")
			return
		}
		entry, err := archive.Create(filename)
		if err != nil {
			rt.internalError(w, r, "create certificate archive entry", err)
			return
		}
		if _, err := entry.Write(content); err != nil {
			rt.internalError(w, r, "write certificate archive entry", err)
			return
		}
	}
	readme, err := archive.Create("README.txt")
	if err != nil {
		rt.internalError(w, r, "create certificate archive readme", err)
		return
	}
	_, _ = fmt.Fprintf(readme, "%s certificate bundle\n\nCertificate: %s\nPrimary domain: %s\nContainer directory: /certs/%s\nPrivate key included: %t\n\nKeep privkey.pem confidential and restrict it to the service account that terminates TLS.\n", rt.config.AppName, value.Name, value.PrimaryDomain, value.OutputDirectory, request.IncludePrivateKey)
	if err := archive.Close(); err != nil {
		rt.internalError(w, r, "close certificate archive", err)
		return
	}
	actor, _ := rt.auth.CurrentUser(r)
	clientIP := auth.ClientIP(r, rt.config.TrustsProxy(r.RemoteAddr))
	_ = rt.certificates.AuditFileAccess(r.Context(), value.ID, "certificate_files.archive_download", actor, clientIP)
	if request.IncludePrivateKey {
		_ = rt.certificates.AuditFileAccess(r.Context(), value.ID, "private_key.archive_download", actor, clientIP)
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="certificate-bundle.zip"`)
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buffer.Bytes())
}

func (rt *Router) revealPrivateKey(w http.ResponseWriter, r *http.Request) {
	var request passwordRequest
	if err := decodeJSON(w, r, &request, maxAuthBody); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "请求格式无效")
		return
	}
	if err := rt.auth.Reauthenticate(w, r, request.Password); err != nil {
		request.Password = ""
		writeError(w, http.StatusUnauthorized, "AUTH_REAUTH_REQUIRED", "管理员密码错误")
		return
	}
	request.Password = ""
	chiContext := chi.RouteContext(r.Context())
	chiContext.URLParams.Add("type", "private-key")
	w.Header().Set("Cache-Control", "no-store, private")
	rt.serveCertificateFile(w, r, false)
}

func (rt *Router) auditPrivateKeyCopy(w http.ResponseWriter, r *http.Request) {
	if !rt.auth.Reauthenticated(r) {
		writeError(w, http.StatusForbidden, "AUTH_REAUTH_REQUIRED", "复制私钥前必须重新认证")
		return
	}
	if _, ok := rt.certificateByID(w, r); !ok {
		return
	}
	id := chi.URLParam(r, "id")
	actor, _ := rt.auth.CurrentUser(r)
	if err := rt.certificates.AuditFileAccess(r.Context(), id, "private_key.copy", actor, auth.ClientIP(r, rt.config.TrustsProxy(r.RemoteAddr))); err != nil {
		rt.internalError(w, r, "audit private key copy", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (rt *Router) serveCertificateFile(w http.ResponseWriter, r *http.Request, download bool) {
	fileType := chi.URLParam(r, "type")
	filename, ok := certificateFileNames[fileType]
	if !ok {
		writeError(w, http.StatusBadRequest, "CERT_FILE_NOT_FOUND", "不支持的证书文件类型")
		return
	}
	id := chi.URLParam(r, "id")
	content, err := rt.certificates.ReadFile(r.Context(), id, filename)
	if errors.Is(err, certificate.ErrNotFound) {
		writeError(w, http.StatusNotFound, "CERT_NOT_FOUND", "证书不存在")
		return
	}
	if err != nil {
		writeError(w, http.StatusNotFound, "CERT_FILE_NOT_FOUND", "证书文件不存在")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if fileType == "private-key" {
		w.Header().Set("Cache-Control", "no-store, private")
		actor, _ := rt.auth.CurrentUser(r)
		eventType := "private_key.view"
		if download {
			eventType = "private_key.download"
		}
		_ = rt.certificates.AuditFileAccess(r.Context(), id, eventType, actor, auth.ClientIP(r, rt.config.TrustsProxy(r.RemoteAddr)))
	}
	if download {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (rt *Router) certificateByID(w http.ResponseWriter, r *http.Request) (certificate.Certificate, bool) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	value, err := rt.certificates.Get(r.Context(), id)
	if errors.Is(err, certificate.ErrNotFound) {
		writeError(w, http.StatusNotFound, "CERT_NOT_FOUND", "证书不存在")
		return certificate.Certificate{}, false
	}
	if err != nil {
		rt.internalError(w, r, "get certificate", err)
		return certificate.Certificate{}, false
	}
	return value, true
}

func (rt *Router) internalError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	rt.logger.ErrorContext(r.Context(), operation, "error", err)
	writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "服务器内部错误")
}
