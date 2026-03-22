package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRateLimiterAllows(t *testing.T) {
	rl := newRateLimiter(2, 3)
	ip := "192.168.1.1"

	for i := 0; i < 3; i++ {
		if !rl.allow(ip) {
			t.Fatalf("request %d should be allowed (within burst)", i+1)
		}
	}
}

func TestRateLimiterBlocks(t *testing.T) {
	rl := newRateLimiter(2, 1)
	ip := "192.168.1.1"

	if !rl.allow(ip) {
		t.Fatal("first request should be allowed")
	}
	if rl.allow(ip) {
		t.Fatal("second request should be blocked (burst=1, rate=2/min)")
	}
}

func TestRateLimiterPerIP(t *testing.T) {
	rl := newRateLimiter(2, 1)

	if !rl.allow("1.1.1.1") {
		t.Fatal("first IP should be allowed")
	}
	if !rl.allow("2.2.2.2") {
		t.Fatal("second IP should be allowed (different IP)")
	}
	if rl.allow("1.1.1.1") {
		t.Fatal("first IP should be blocked on second request")
	}
}

func TestPublicServesSignupPage(t *testing.T) {
	handler := newPublicHandler("http://localhost:9999")

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "K8s Learning Lab") {
		t.Fatal("signup page should contain 'K8s Learning Lab'")
	}
}

func TestPublicServesTasksPage(t *testing.T) {
	handler := newPublicHandler("http://localhost:9999")

	req := httptest.NewRequest("GET", "/tasks", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "K8s Learning Tasks") {
		t.Fatal("tasks page should contain 'K8s Learning Tasks'")
	}
}

func TestPublicWebhookProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "n8n.local.bp31app.com" {
			t.Errorf("expected Host header n8n.local.bp31app.com, got %s", r.Host)
		}
		w.WriteHeader(200)
		w.Write([]byte("webhook-ok"))
	}))
	defer upstream.Close()

	handler := newPublicHandler(upstream.URL)

	req := httptest.NewRequest("POST", "/webhook/k8s-learn-signup", strings.NewReader(`{"name":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "webhook-ok" {
		t.Fatalf("expected proxied response, got %q", w.Body.String())
	}
}

func TestPublicWebhookRateLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	handler := newPublicHandler(upstream.URL)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/webhook/k8s-learn-signup", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	req := httptest.NewRequest("POST", "/webhook/k8s-learn-signup", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 429 {
		t.Fatalf("4th request: expected 429, got %d", w.Code)
	}
}

func TestPublicUnknownWebhook404(t *testing.T) {
	handler := newPublicHandler("http://localhost:9999")

	req := httptest.NewRequest("POST", "/webhook/unknown-path", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 404 {
		t.Fatalf("expected 404 for unknown webhook, got %d", w.Code)
	}
}

func TestPublicServesTasksOnTasksHost(t *testing.T) {
	handler := newPublicHandler("http://localhost:9999")

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "learn-tasks.bp31app.com"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "K8s Learning Tasks") {
		t.Fatal("tasks host should serve tasks page, not signup")
	}
}

func TestPublicServesSignupOnDefaultHost(t *testing.T) {
	handler := newPublicHandler("http://localhost:9999")

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "learn.bp31app.com"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Sign Up") {
		t.Fatal("default host should serve signup page")
	}
}
