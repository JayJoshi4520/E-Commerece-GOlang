package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"
)

type limiter struct {
	mu     sync.Mutex
	perKey map[string]*rate.Limiter
	r      rate.Limit
	b      int
}

func newLimiter(r rate.Limit, b int) *limiter {
	return &limiter{
		perKey: map[string]*rate.Limiter{},
		r:      r,
		b:      b,
	}
}

func (l *limiter) get(key string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	lt, ok := l.perKey[key]
	if ok {
		return lt
	}
	lt = rate.NewLimiter(l.r, l.b)
	l.perKey[key] = lt
	return lt
}

func (l *limiter) allow(key string) bool {
	return l.get(key).Allow()
}

func ipOrTokenKey(r *http.Request) string {
	a := r.Header.Get("Authorization")
	if strings.HasPrefix(a, "Bearer ") {
		return "tok:" + a[7:]
	}
	return "ip:" + strings.Split(r.RemoteAddr, ":")[0]
}

func rateLimit(l *limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := ipOrTokenKey(r)
			if !l.allow(key) {
				w.WriteHeader(429)
				w.Write([]byte(`{"error": "rate limit"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func proxyTo(target string) http.HandlerFunc {
	u, _ := url.Parse(target)
	p := httputil.NewSingleHostReverseProxy(u)
	return func(w http.ResponseWriter, r *http.Request) {
		p.ServeHTTP(w, r)
	}
}

func main() {
	r := chi.NewRouter()

	rl := newLimiter(10, 20)
	r.Use(rateLimit(rl))

	r.Mount("/api/auth", http.StripPrefix("/api/auth", proxyTo("http://localhost:8081")))
	r.Mount("/api/catalog", http.StripPrefix("/api/catalog", proxyTo("http://localhost:8082")))
	r.Mount("/api/order", http.StripPrefix("/api/order", proxyTo("http://localhost:8083")))
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	log.Println("gateway listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
