package httpapi

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/go-chi/chi/v5"
)

var challengeTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func (rt *Router) acmeHTTPChallenge(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if !challengeTokenPattern.MatchString(token) {
		http.NotFound(w, r)
		return
	}
	rootInfo, err := os.Lstat(rt.config.ACMEChallengeDir)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		http.NotFound(w, r)
		return
	}
	filename := filepath.Join(rt.config.ACMEChallengeDir, token)
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		http.NotFound(w, r)
		return
	}
	file, err := os.Open(filename)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	if _, err := file.Stat(); err != nil && !errors.Is(err, os.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, token, info.ModTime(), file)
}
