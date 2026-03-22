package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashMode(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "password-hash")
	t.Setenv("TERM_PASS", "testpass123")

	err := runHashMode(outPath)
	if err != nil {
		t.Fatalf("runHashMode failed: %v", err)
	}

	hash, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read hash file: %v", err)
	}

	if err := bcrypt.CompareHashAndPassword(hash, []byte("testpass123")); err != nil {
		t.Fatalf("bcrypt hash does not match password: %v", err)
	}
}

func TestHashModeMissingEnv(t *testing.T) {
	t.Setenv("TERM_PASS", "")
	err := runHashMode("/tmp/test-hash")
	if err == nil {
		t.Fatal("expected error when TERM_PASS not set")
	}
}

func TestSignAndValidateCookie(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-ok!!!")
	value := signCookie(secret, 3600)
	if value == "" {
		t.Fatal("signCookie returned empty string")
	}
	err := validateCookie(secret, value)
	if err != nil {
		t.Fatalf("validateCookie failed: %v", err)
	}
}

func TestValidateCookieExpired(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-ok!!!")
	value := signCookie(secret, -1)
	err := validateCookie(secret, value)
	if err == nil {
		t.Fatal("expected error for expired cookie")
	}
}

func TestValidateCookieTampered(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-ok!!!")
	value := signCookie(secret, 3600)
	err := validateCookie(secret, value+"tampered")
	if err == nil {
		t.Fatal("expected error for tampered cookie")
	}
}

func TestValidateCookieWrongSecret(t *testing.T) {
	secret1 := []byte("secret-one-32-bytes-long-ok!!!!")
	secret2 := []byte("secret-two-32-bytes-long-ok!!!!")
	value := signCookie(secret1, 3600)
	err := validateCookie(secret2, value)
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestValidateToken(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	os.WriteFile(tokenPath, []byte("abc123def456"), 0600)

	err := validateToken(tokenPath, "abc123def456")
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
}

func TestValidateTokenWrongValue(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	os.WriteFile(tokenPath, []byte("abc123def456"), 0600)

	err := validateToken(tokenPath, "wrong")
	if err == nil {
		t.Fatal("expected error for wrong token")
	}
}

func TestValidateTokenMissingFile(t *testing.T) {
	err := validateToken("/nonexistent/token", "abc123")
	if err == nil {
		t.Fatal("expected error for missing token file")
	}
}

func TestConsumeToken(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	os.WriteFile(tokenPath, []byte("abc123def456"), 0600)

	consumeToken(tokenPath)

	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatal("token file should be deleted after consumption")
	}
}

func TestLoginPageContainsForm(t *testing.T) {
	html := renderLoginPage("")
	if !strings.Contains(html, "<form") {
		t.Fatal("login page missing form element")
	}
	if !strings.Contains(html, "password") {
		t.Fatal("login page missing password field")
	}
}

func TestLoginPageShowsError(t *testing.T) {
	html := renderLoginPage("Invalid password")
	if !strings.Contains(html, "Invalid password") {
		t.Fatal("login page should display error message")
	}
}

func TestLogoutPageContent(t *testing.T) {
	html := renderLogoutPage()
	if !strings.Contains(html, "logged out") && !strings.Contains(html, "Logged out") {
		t.Fatal("logout page should say logged out")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	for _, k := range []string{"AUTH_HASH_PATH", "AUTH_TOKEN_PATH", "AUTH_COOKIE_SECRET_PATH", "AUTH_UPSTREAM", "AUTH_COOKIE_MAX_AGE"} {
		t.Setenv(k, "")
	}
	cfg := loadConfig()
	if cfg.HashPath != "/auth/password-hash" {
		t.Fatalf("expected default hash path, got %s", cfg.HashPath)
	}
	if cfg.TokenPath != "/auth/token" {
		t.Fatalf("expected default token path, got %s", cfg.TokenPath)
	}
	if cfg.Upstream != "http://localhost:7681" {
		t.Fatalf("expected default upstream, got %s", cfg.Upstream)
	}
	if cfg.CookieMaxAge != 86400 {
		t.Fatalf("expected 86400, got %d", cfg.CookieMaxAge)
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv("AUTH_UPSTREAM", "http://localhost:9999")
	t.Setenv("AUTH_COOKIE_MAX_AGE", "3600")
	cfg := loadConfig()
	if cfg.Upstream != "http://localhost:9999" {
		t.Fatalf("expected env override, got %s", cfg.Upstream)
	}
	if cfg.CookieMaxAge != 3600 {
		t.Fatalf("expected 3600, got %d", cfg.CookieMaxAge)
	}
}

// Helper: create a test server with a mock upstream
func setupTestServer(t *testing.T) (*httptest.Server, config) {
	t.Helper()
	dir := t.TempDir()

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.MinCost)
	hashPath := filepath.Join(dir, "password-hash")
	os.WriteFile(hashPath, hash, 0600)

	tokenPath := filepath.Join(dir, "token")
	os.WriteFile(tokenPath, []byte("valid-token-123"), 0600)

	secretPath := filepath.Join(dir, "cookie-secret")
	os.WriteFile(secretPath, generateSecret(), 0600)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ttyd-upstream"))
	}))
	t.Cleanup(upstream.Close)

	cfg := config{
		HashPath:         hashPath,
		TokenPath:        tokenPath,
		CookieSecretPath: secretPath,
		Upstream:         upstream.URL,
		CookieMaxAge:     86400,
	}
	return upstream, cfg
}

func TestGetLoginPage(t *testing.T) {
	_, cfg := setupTestServer(t)
	secret, _ := os.ReadFile(cfg.CookieSecretPath)
	handler := newAuthHandler(cfg, secret)

	req := httptest.NewRequest("GET", "/auth/login", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "<form") {
		t.Fatal("response should contain login form")
	}
}

func TestPostLoginSuccess(t *testing.T) {
	_, cfg := setupTestServer(t)
	secret, _ := os.ReadFile(cfg.CookieSecretPath)
	handler := newAuthHandler(cfg, secret)

	form := url.Values{"password": {"testpass"}}
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", w.Code)
	}
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "session" {
			found = true
			if !c.HttpOnly {
				t.Error("cookie should be HttpOnly")
			}
			if !c.Secure {
				t.Error("cookie should be Secure")
			}
			if c.SameSite != http.SameSiteStrictMode {
				t.Error("cookie should be SameSite=Strict")
			}
		}
	}
	if !found {
		t.Fatal("session cookie not set")
	}
}

func TestPostLoginWrongPassword(t *testing.T) {
	_, cfg := setupTestServer(t)
	secret, _ := os.ReadFile(cfg.CookieSecretPath)
	handler := newAuthHandler(cfg, secret)

	form := url.Values{"password": {"wrongpass"}}
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 with error page, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid password") {
		t.Fatal("should show error message")
	}
}

func TestTokenRedemption(t *testing.T) {
	_, cfg := setupTestServer(t)
	secret, _ := os.ReadFile(cfg.CookieSecretPath)
	handler := newAuthHandler(cfg, secret)

	req := httptest.NewRequest("GET", "/?token=valid-token-123", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", w.Code)
	}
	if _, err := os.Stat(cfg.TokenPath); !os.IsNotExist(err) {
		t.Fatal("token file should be deleted after redemption")
	}
}

func TestTokenRedemptionInvalid(t *testing.T) {
	_, cfg := setupTestServer(t)
	secret, _ := os.ReadFile(cfg.CookieSecretPath)
	handler := newAuthHandler(cfg, secret)

	req := httptest.NewRequest("GET", "/?token=wrong-token", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect to login, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/auth/login" {
		t.Fatalf("expected redirect to /auth/login, got %s", loc)
	}
}

func TestTokenDoubleUse(t *testing.T) {
	_, cfg := setupTestServer(t)
	secret, _ := os.ReadFile(cfg.CookieSecretPath)
	handler := newAuthHandler(cfg, secret)

	req1 := httptest.NewRequest("GET", "/?token=valid-token-123", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusSeeOther {
		t.Fatalf("first token use: expected 303, got %d", w1.Code)
	}

	req2 := httptest.NewRequest("GET", "/?token=valid-token-123", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	loc := w2.Header().Get("Location")
	if loc != "/auth/login" {
		t.Fatalf("second token use should redirect to /auth/login, got %s", loc)
	}
}

func TestAuthenticatedProxying(t *testing.T) {
	_, cfg := setupTestServer(t)
	secret, _ := os.ReadFile(cfg.CookieSecretPath)
	handler := newAuthHandler(cfg, secret)

	cookieVal := signCookie(secret, 86400)
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: cookieVal})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 from proxy, got %d", w.Code)
	}
	if w.Body.String() != "ttyd-upstream" {
		t.Fatalf("expected proxied response, got %q", w.Body.String())
	}
}

func TestUnauthenticatedRedirect(t *testing.T) {
	_, cfg := setupTestServer(t)
	secret, _ := os.ReadFile(cfg.CookieSecretPath)
	handler := newAuthHandler(cfg, secret)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", w.Code)
	}
	if w.Header().Get("Location") != "/auth/login" {
		t.Fatalf("expected redirect to /auth/login")
	}
}

func TestLogout(t *testing.T) {
	_, cfg := setupTestServer(t)
	secret, _ := os.ReadFile(cfg.CookieSecretPath)
	handler := newAuthHandler(cfg, secret)

	req := httptest.NewRequest("GET", "/auth/logout", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "session" && c.MaxAge > 0 {
			t.Fatal("session cookie should be cleared (MaxAge <= 0)")
		}
	}
}

func TestExpiredCookieRedirects(t *testing.T) {
	_, cfg := setupTestServer(t)
	secret, _ := os.ReadFile(cfg.CookieSecretPath)
	handler := newAuthHandler(cfg, secret)

	cookieVal := signCookie(secret, -1)
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: cookieVal})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect for expired cookie, got %d", w.Code)
	}
}

func TestHashModeCopiesToken(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "password-hash")
	secretDir := filepath.Join(dir, "secret")
	os.Mkdir(secretDir, 0755)
	os.WriteFile(filepath.Join(secretDir, "token"), []byte("mytoken"), 0600)

	t.Setenv("TERM_PASS", "testpass123")
	t.Setenv("AUTH_SECRET_TOKEN_PATH", filepath.Join(secretDir, "token"))
	t.Setenv("AUTH_TOKEN_PATH", filepath.Join(dir, "token"))

	if err := runHashMode(outPath); err != nil {
		t.Fatalf("runHashMode failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "token"))
	if err != nil {
		t.Fatalf("token not copied: %v", err)
	}
	if string(data) != "mytoken" {
		t.Fatalf("token content mismatch: got %q", string(data))
	}
}
