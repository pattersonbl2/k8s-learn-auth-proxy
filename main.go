package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func runHashMode(outPath string) error {
	pass := os.Getenv("TERM_PASS")
	if pass == "" {
		return fmt.Errorf("TERM_PASS environment variable not set")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt hash failed: %w", err)
	}
	if err := os.WriteFile(outPath, hash, 0600); err != nil {
		return fmt.Errorf("write hash: %w", err)
	}

	// Copy token from secret mount to emptyDir (if source exists)
	srcToken := envOrDefault("AUTH_SECRET_TOKEN_PATH", "/auth-secret/token")
	dstToken := envOrDefault("AUTH_TOKEN_PATH", "/auth/token")
	if data, err := os.ReadFile(srcToken); err == nil {
		if err := os.WriteFile(dstToken, data, 0600); err != nil {
			return fmt.Errorf("copy token: %w", err)
		}
	}
	return nil
}

func main() {
	hashMode := flag.Bool("hash", false, "Hash TERM_PASS env var and write to /auth/password-hash")
	mode := flag.String("mode", "auth", "Server mode: 'auth' (sidecar) or 'public' (signup/tasks)")
	webhookUpstream := flag.String("webhook-upstream", "http://192.168.50.97:80", "n8n webhook upstream URL")
	flag.Parse()

	if *hashMode {
		if err := runHashMode(envOrDefault("AUTH_HASH_PATH", "/auth/password-hash")); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	switch *mode {
	case "public":
		handler := newPublicHandler(*webhookUpstream)
		log.Printf("k8s-learn public mode listening on :8080, webhook-upstream=%s", *webhookUpstream)
		if err := http.ListenAndServe(":8080", handler); err != nil {
			log.Fatalf("server error: %v", err)
		}
	case "auth":
		cfg := loadConfig()
		cookieSecret := generateSecret()
		if err := os.WriteFile(cfg.CookieSecretPath, cookieSecret, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "error writing cookie secret: %v\n", err)
			os.Exit(1)
		}
		handler := newAuthHandler(cfg, cookieSecret)
		log.Printf("k8s-learn auth mode listening on :8080, upstream=%s", cfg.Upstream)
		if err := http.ListenAndServe(":8080", handler); err != nil {
			log.Fatalf("server error: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown mode: %s (use 'auth' or 'public')\n", *mode)
		os.Exit(1)
	}
}

type cookiePayload struct {
	Exp int64 `json:"exp"`
}

func signCookie(secret []byte, maxAgeSec int) string {
	payload := cookiePayload{Exp: time.Now().Unix() + int64(maxAgeSec)}
	data, err := json.Marshal(payload)
	if err != nil {
		panic("failed to marshal cookie payload: " + err.Error())
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(encoded))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encoded + "." + sig
}

func validateCookie(secret []byte, value string) error {
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid cookie format")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0]))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return fmt.Errorf("invalid signature")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("invalid payload encoding: %w", err)
	}
	var p cookiePayload
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}
	if time.Now().Unix() > p.Exp {
		return fmt.Errorf("cookie expired")
	}
	return nil
}

func generateSecret() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random secret: " + err.Error())
	}
	return b
}

func validateToken(tokenPath, candidate string) error {
	stored, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("token file not found: %w", err)
	}
	storedStr := strings.TrimSpace(string(stored))
	if subtle.ConstantTimeCompare([]byte(storedStr), []byte(candidate)) != 1 {
		return fmt.Errorf("token mismatch")
	}
	return nil
}

func consumeToken(tokenPath string) {
	os.Remove(tokenPath)
}

type config struct {
	HashPath         string
	TokenPath        string
	CookieSecretPath string
	Upstream         string
	CookieMaxAge     int
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func newAuthHandler(cfg config, cookieSecret []byte) http.Handler {
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		log.Fatalf("invalid upstream URL: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /auth/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(renderLoginPage("")))
	})

	mux.HandleFunc("POST /auth/login", func(w http.ResponseWriter, r *http.Request) {
		password := r.FormValue("password")
		hashBytes, err := os.ReadFile(cfg.HashPath)
		if err != nil {
			log.Printf("error reading hash file: %v", err)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(renderLoginPage("Internal error")))
			return
		}
		if err := bcrypt.CompareHashAndPassword(hashBytes, []byte(password)); err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(renderLoginPage("Invalid password")))
			return
		}
		setSessionCookie(w, cookieSecret, cfg.CookieMaxAge)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	mux.HandleFunc("GET /auth/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(renderLogoutPage()))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if token := r.URL.Query().Get("token"); token != "" {
			if err := validateToken(cfg.TokenPath, token); err == nil {
				consumeToken(cfg.TokenPath)
				setSessionCookie(w, cookieSecret, cfg.CookieMaxAge)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		cookie, err := r.Cookie("session")
		if err != nil || validateCookie(cookieSecret, cookie.Value) != nil {
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		proxy.ServeHTTP(w, r)
	})

	return mux
}

func setSessionCookie(w http.ResponseWriter, secret []byte, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    signCookie(secret, maxAge),
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func loadConfig() config {
	maxAge := 86400
	if v := os.Getenv("AUTH_COOKIE_MAX_AGE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxAge = n
		}
	}
	return config{
		HashPath:         envOrDefault("AUTH_HASH_PATH", "/auth/password-hash"),
		TokenPath:        envOrDefault("AUTH_TOKEN_PATH", "/auth/token"),
		CookieSecretPath: envOrDefault("AUTH_COOKIE_SECRET_PATH", "/auth/cookie-secret"),
		Upstream:         envOrDefault("AUTH_UPSTREAM", "http://localhost:7681"),
		CookieMaxAge:     maxAge,
	}
}
