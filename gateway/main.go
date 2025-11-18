package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/go-chi/chi/v5"
)

func proxyTo(target string) http.HandlerFunc {
	u, _ := url.Parse(target)
	p := httputil.NewSingleHostReverseProxy(u)
	return func(w http.ResponseWriter, r *http.Request) {
		p.ServeHTTP(w, r)
	}
}

func main() {
	r := chi.NewRouter()
	r.Mount("/api/auth", http.StripPrefix("/api/auth", proxyTo("http://localhost:8081")))
	r.Mount("/api/catalog", http.StripPrefix("/api/catalog", proxyTo("http://localhost:8082")))
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	log.Println("gateway listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
