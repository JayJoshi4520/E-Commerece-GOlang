package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/bcrypt"
)

type ctxKey string

const (
	ctxKeyEmail ctxKey = "email"
	ctxKeyRole  ctxKey = "role"
)

type Server struct {
	db            *pgxpool.Pool
	jwt           []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
	cookieName    string
	cookieDomain  string
	secureCookies bool
}

type creds struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role,omitempty"`
}

func loadENV() error {
	err := godotenv.Load()
	if err != nil {
		err = godotenv.Load(".env")
		if err != nil {
			return fmt.Errorf("error loading .env file: %v", err)
		}
	}
	return nil
}

func getenv(k, d string) string {
	v := os.Getenv(k)
	if v != "" {
		return v
	}
	return d
}

func randomB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func random32() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func dur(s string) time.Duration {
	d, _ := time.ParseDuration(s)
	if d == 0 {
		return 24 * time.Hour
	}
	return d
}

func main() {
	if err := loadENV(); err != nil {
		log.Printf("Warning: %v", err)
		log.Println("Continuing with system environment variables...")
	}

	dbURL := getenv("DATABASE_URL", "postgres://app:example@localhost:5432/app?sslmode=disable")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	jwtSecret := []byte(getenv("JWT_SECRET", random32()))
	accessTTL := dur(getenv("ACCESS_TTL", "15m"))
	// fixed env var name
	refreshTTL := dur(getenv("REFRESH_TTL", "720h"))
	cookieDomain := getenv("COOKIE_DOMAIN", "localhost")
	secureCookies := getenv("COOKIE_SECURE", "false") == "true"

	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}
	defer pool.Close()

	err = pool.Ping(context.Background())
	if err != nil {
		log.Fatalf("Unable to ping database: %v", err)
	}

	s := &Server{
		db:            pool,
		jwt:           jwtSecret,
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
		cookieName:    "rt",
		cookieDomain:  cookieDomain,
		secureCookies: secureCookies,
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Handle("/metrics", promhttp.Handler())

	r.Post("/v1/auth/register", s.register)
	r.Post("/v1/auth/login", s.login)
	r.Post("/v1/auth/refresh", s.refresh)
	r.Post("/v1/auth/logout", s.logout)
	r.With(s.authn).Get("/v1/auth/me", s.me)

	log.Println("auth listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", r))
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var c creds
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil || len(c.Email) < 3 || len(c.Password) < 8 {
		http.Error(w, "invalid fields", http.StatusBadRequest)
		return
	}

	role := "buyer"
	if c.Role == "seller" {
		role = "seller"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(c.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "unable to hash password", http.StatusInternalServerError)
		return
	}
	_, err = s.db.Exec(r.Context(),
		"INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) ON CONFLICT (email) DO NOTHING",
		strings.ToLower(c.Email), string(hash), role)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var c creds
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	var hash, role string
	emailLower := strings.ToLower(c.Email)

	err := s.db.QueryRow(r.Context(),
		"SELECT password_hash, role FROM users WHERE email=$1", emailLower).Scan(&hash, &role)

	if err != nil {
		log.Printf("Login failed for email %s. DB error: %v", emailLower, err)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(c.Password)) != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	access, err := s.signAccess(c.Email, role)
	if err != nil {
		http.Error(w, "signing error", http.StatusInternalServerError)
		return
	}

	rawRT := randomB64(48)
	rtHash, err := bcrypt.GenerateFromPassword([]byte(rawRT), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "unable to generate refresh token", http.StatusInternalServerError)
		return
	}
	expires := time.Now().Add(s.refreshTTL)
	_, err = s.db.Exec(r.Context(),
		"INSERT INTO refresh_tokens (user_email, token_hash, user_agent, ip_addr, expires_at) VALUES ($1, $2, $3, $4, $5)",
		strings.ToLower(c.Email), string(rtHash), r.UserAgent(), clientIP(r), expires)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.setRefreshCookie(w, rawRT, int(s.refreshTTL.Seconds()))
	_ = json.NewEncoder(w).Encode(map[string]any{"token": access, "role": role})
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie(s.cookieName)
	if err != nil || ck.Value == "" {
		http.Error(w, "missing refresh", http.StatusBadRequest)
		return
	}
	rawRT := ck.Value

	var email, tokenHash string
	var expires time.Time
	var revoked bool

	rows, err := s.db.Query(r.Context(),
		"SELECT user_email, token_hash, expires_at, revoked FROM refresh_tokens WHERE revoked = false AND expires_at > now()")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var matchEmail, matchHash string

	ok := false

	for rows.Next() {
		if rows.Scan(&email, &tokenHash, &expires, &revoked) != nil {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(tokenHash), []byte(rawRT)) == nil {
			ok = true
			matchEmail = email
			matchHash = tokenHash
			break
		}
	}

	if !ok {
		http.Error(w, "invalid refresh", http.StatusBadRequest)
		return
	}

	var role string
	if s.db.QueryRow(r.Context(),
		"SELECT role FROM users WHERE email=$1", matchEmail).Scan(&role) != nil {
		http.Error(w, "user not found", http.StatusUnauthorized)
		return
	}
	_, _ = s.db.Exec(r.Context(),
		"UPDATE refresh_tokens SET revoked=true WHERE token_hash=$1", matchHash)

	newRaw := randomB64(48)
	newHash, _ := bcrypt.GenerateFromPassword([]byte(newRaw), bcrypt.DefaultCost)
	_, _ = s.db.Exec(r.Context(),
		"INSERT INTO refresh_tokens (user_email, token_hash, user_agent, ip_addr, expires_at) VALUES ($1,$2,$3,$4,$5)",
		matchEmail, string(newHash), r.UserAgent(), clientIP(r), time.Now().Add(s.refreshTTL))
	s.setRefreshCookie(w, newRaw, int(s.refreshTTL.Seconds()))
	access, _ := s.signAccess(matchEmail, role)
	_ = json.NewEncoder(w).Encode(map[string]any{"token": access, "role": role})

}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie(s.cookieName)
	if err == nil && ck.Value != "" {
		rows, _ := s.db.Query(r.Context(), "SELECT token_hash FROM refresh_tokens WHERE revoked=false")
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var th string
				if rows.Scan(&th) == nil && bcrypt.CompareHashAndPassword([]byte(th), []byte(ck.Value)) == nil {
					_, _ = s.db.Exec(r.Context(), "UPDATE refresh_tokens SET revoked=true WHERE token_hash=$1", th)
					break
				}
			}
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.cookieDomain,
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) setRefreshCookie(w http.ResponseWriter, raw string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    raw,
		Path:     "/",
		Domain:   s.cookieDomain,
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func (s *Server) requireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Context().Value(ctxKeyRole) != role {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) authn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if len(auth) < 8 || auth[:7] != "Bearer " {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		tok, err := jwt.Parse(auth[7:], func(t *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return s.jwt, nil
		})
		if err != nil || !tok.Valid {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		// attach claims to context so handlers can access email/role
		if claims, ok := tok.Claims.(jwt.MapClaims); ok {
			ctx := r.Context()
			if em, ok := claims["email"].(string); ok {
				ctx = context.WithValue(ctx, ctxKeyEmail, em)
			}
			if rl, ok := claims["role"].(string); ok {
				ctx = context.WithValue(ctx, ctxKeyRole, rl)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	email, _ := r.Context().Value(ctxKeyEmail).(string)
	role, _ := r.Context().Value(ctxKeyRole).(string)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "email": email, "role": role})
}

func (s *Server) signAccess(email, role string) (string, error) {
	claims := jwt.MapClaims{
		"email": email,
		"role":  role,
		"exp":   time.Now().Add(s.accessTTL).Unix(),
		"iat":   time.Now().Unix(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(s.jwt)
}

func clientIP(r *http.Request) string {
	// X-Forwarded-For may be a comma-separated list
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		parts := strings.Split(xf, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return xr
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
