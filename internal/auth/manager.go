package auth

import (
	"crypto/sha512"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/rin721/certmate/internal/config"
	"github.com/rin721/certmate/internal/project"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionAuthenticated = "authenticated"
	sessionUsername      = "username"
	sessionCreatedAt     = "created_at"
	sessionReauthAt      = "reauth_at"
)

type Manager struct {
	username     string
	passwordHash []byte
	store        *sessions.CookieStore
	cookieName   string
	cookie       *sessions.Options
	limiter      *LoginLimiter
	reauthTTL    time.Duration
	now          func() time.Time
}

func NewManager(cfg config.Config) *Manager {
	keys := sha512.Sum512(append([]byte("certmate/session/v1:"), cfg.SessionSecret...))
	store := sessions.NewCookieStore(keys[:32], keys[32:])
	options := &sessions.Options{
		Path:     "/",
		MaxAge:   int(cfg.SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   cfg.SessionCookieSecure,
		SameSite: http.SameSiteStrictMode,
	}
	store.Options = options
	return &Manager{
		username:     cfg.AdminUsername,
		passwordHash: append([]byte(nil), cfg.AdminPasswordHash...),
		store:        store,
		cookieName:   project.Slug + "_session",
		cookie:       options,
		limiter:      NewLoginLimiter(),
		reauthTTL:    5 * time.Minute,
		now:          time.Now,
	}
}

func (m *Manager) Authenticate(clientKey, username, password string) error {
	key := clientKey + "\x00" + strings.ToLower(strings.TrimSpace(username))
	if !m.limiter.Allow(key) {
		return ErrRateLimited
	}
	usernameOK := subtle.ConstantTimeCompare([]byte(username), []byte(m.username)) == 1
	passwordOK := bcrypt.CompareHashAndPassword(m.passwordHash, []byte(password)) == nil
	if !usernameOK || !passwordOK {
		m.limiter.Failure(key)
		return ErrInvalidCredentials
	}
	m.limiter.Success(key)
	return nil
}

func (m *Manager) Login(w http.ResponseWriter, r *http.Request) error {
	session, err := m.store.Get(r, m.cookieName)
	if err != nil {
		session, _ = m.store.New(r, m.cookieName)
	}
	session.Options = cloneOptions(m.cookie)
	session.Values[sessionAuthenticated] = true
	session.Values[sessionUsername] = m.username
	session.Values[sessionCreatedAt] = m.now().Unix()
	delete(session.Values, sessionReauthAt)
	return m.store.Save(r, w, session)
}

func (m *Manager) Logout(w http.ResponseWriter, r *http.Request) error {
	session, _ := m.store.Get(r, m.cookieName)
	session.Values = make(map[any]any)
	session.Options = cloneOptions(m.cookie)
	session.Options.MaxAge = -1
	return m.store.Save(r, w, session)
}

func (m *Manager) CurrentUser(r *http.Request) (string, bool) {
	session, err := m.store.Get(r, m.cookieName)
	if err != nil {
		return "", false
	}
	authenticated, _ := session.Values[sessionAuthenticated].(bool)
	username, _ := session.Values[sessionUsername].(string)
	createdAt, _ := session.Values[sessionCreatedAt].(int64)
	if !authenticated || username != m.username || createdAt == 0 || m.now().After(time.Unix(createdAt, 0).Add(time.Duration(m.cookie.MaxAge)*time.Second)) {
		return "", false
	}
	return username, true
}

func (m *Manager) Reauthenticate(w http.ResponseWriter, r *http.Request, password string) error {
	if _, ok := m.CurrentUser(r); !ok {
		return ErrUnauthenticated
	}
	if bcrypt.CompareHashAndPassword(m.passwordHash, []byte(password)) != nil {
		return ErrInvalidCredentials
	}
	session, err := m.store.Get(r, m.cookieName)
	if err != nil {
		return err
	}
	session.Values[sessionReauthAt] = m.now().Unix()
	return m.store.Save(r, w, session)
}

func (m *Manager) Reauthenticated(r *http.Request) bool {
	if _, ok := m.CurrentUser(r); !ok {
		return false
	}
	session, err := m.store.Get(r, m.cookieName)
	if err != nil {
		return false
	}
	value, ok := session.Values[sessionReauthAt].(int64)
	return ok && m.now().Sub(time.Unix(value, 0)) <= m.reauthTTL
}

func cloneOptions(value *sessions.Options) *sessions.Options {
	copy := *value
	return &copy
}

func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); forwarded != "" {
			return forwarded
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr == "" {
		return "unknown"
	}
	return strings.Trim(r.RemoteAddr, "[]")
}
