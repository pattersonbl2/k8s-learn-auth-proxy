package main

import (
	_ "embed"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

//go:embed pages/signup.html
var signupHTML []byte

//go:embed pages/tasks.html
var tasksHTML []byte

// --- Rate Limiter ---

type rateLimiter struct {
	limiters map[string]*limiterEntry
	mu       sync.Mutex
	rate     rate.Limit
	burst    int
}

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newRateLimiter(perMinute int, burst int) *rateLimiter {
	rl := &rateLimiter{
		limiters: make(map[string]*limiterEntry),
		rate:     rate.Limit(float64(perMinute) / 60.0),
		burst:    burst,
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, exists := rl.limiters[ip]
	if !exists {
		entry = &limiterEntry{
			limiter: rate.NewLimiter(rl.rate, rl.burst),
		}
		rl.limiters[ip] = entry
	}
	entry.lastSeen = time.Now()
	return entry.limiter.Allow()
}

func (rl *rateLimiter) cleanup() {
	for {
		time.Sleep(time.Minute)
		rl.mu.Lock()
		for ip, entry := range rl.limiters {
			if time.Since(entry.lastSeen) > 10*time.Minute {
				delete(rl.limiters, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// --- Public Handler ---

type signupRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func newPublicHandler(webhookUpstream string, provisioner *Provisioner) http.Handler {
	upstream, err := url.Parse(webhookUpstream)
	if err != nil {
		log.Fatalf("invalid webhook upstream URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		ResponseHeaderTimeout: 60 * time.Second,
	}

	signupRL := newRateLimiter(2, 3)
	helpRL := newRateLimiter(6, 2)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if strings.HasPrefix(r.Host, "learn-tasks") {
			w.Write(tasksHTML)
		} else {
			w.Write(signupHTML)
		}
	})

	mux.HandleFunc("GET /tasks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(tasksHTML)
	})

	mux.HandleFunc("POST /webhook/k8s-learn-signup", func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if !signupRL.allow(ip) {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		if provisioner == nil {
			// Fallback: proxy to n8n (for testing without k8s)
			r.Host = "n8n.local.bp31app.com"
			proxy.ServeHTTP(w, r)
			return
		}

		var req signupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if req.Name == "" || req.Email == "" {
			http.Error(w, "name and email are required", http.StatusBadRequest)
			return
		}

		result, err := provisioner.Provision(r.Context(), req.Name, req.Email)
		if err != nil {
			log.Printf("provisioning failed for %s: %v", req.Name, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "provisioning failed"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"loginUrl": result.LoginURL,
			"password": result.Password,
		})
	})

	mux.HandleFunc("POST /webhook/k8s-learn-help", func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if !helpRL.allow(ip) {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		r.Host = "n8n.local.bp31app.com"
		proxy.ServeHTTP(w, r)
	})

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	return mux
}

func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Real-IP"); xff != "" {
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
