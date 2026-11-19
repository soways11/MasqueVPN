package main

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/soways11/masquevpn/internal/config"
)

func TestFallbackDirConfinesFileReads(t *testing.T) {
	base := t.TempDir()
	site := filepath.Join(base, "site")
	if err := os.Mkdir(site, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		filepath.Join(site, "index.html"): "public page",
		filepath.Join(base, "private"):    "private fixture",
	} {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("index.html", filepath.Join(site, "public.html")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../private", filepath.Join(site, "private")); err != nil {
		t.Fatal(err)
	}
	handler, closeSite, err := buildFallback(&config.Server{FallbackDir: site}, "", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeSite)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/public.html", nil))
	if response.Code != http.StatusOK || response.Body.String() != "public page" {
		t.Fatalf("public file response: %d %q", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/private", nil))
	if response.Code < 400 || response.Body.String() == "private fixture" {
		t.Fatalf("file outside the root was served: HTTP %d", response.Code)
	}
}
