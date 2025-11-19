package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
)

type Server struct{ db *pgxpool.Pool }

type P struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	PriceCents  int    `json:"price_cents"`
	Stock       int    `json:"stock"`
}

func loadENV() error {
	err := godotenv.Load()
	if err != nil {
		err := godotenv.Load(".env")
		log.Fatalf("Error Loading .env: %v", err)
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

var rdb = redis.NewClient(&redis.Options{Addr: "localhost:6379"})

func main() {
	dbURL := getenv("DATABASE_URL", "postgres://app:example@localhost:5432/app?sslmode=disable")
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("Error Creating a Pool: %v", err)
	}
	defer pool.Close()

	s := &Server{db: pool}

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Handle("/metrics", promhttp.Handler())

	r.Get("/v1/products/list", s.list)
	r.Get("/v1/products/{id}", s.get)

	log.Println("catalog listening on :8082")
	log.Fatal(http.ListenAndServe(":8082", r))
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {

	var ctx = r.Context()
	cached, err := rdb.Get(ctx, "catalog:list").Result()
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(cached))
		return
	}

	rows, err := s.db.Query(r.Context(), "SELECT id, title, description, price_cents, stock FROM products ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var productList []P
	for rows.Next() {
		var p P
		if err := rows.Scan(&p.ID, &p.Title, &p.Description, &p.PriceCents, &p.Stock); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		productList = append(productList, p)
	}

	b, _ := json.Marshal(productList)
	rdb.Set(ctx, "catalog:list", b, 60*time.Second)
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := chi.URLParam(r, "id")
	fmt.Print(id)
	var p P
	err := s.db.QueryRow(r.Context(),
		"SELECT id, title, description, price_cents, stock FROM products WHERE id=$1", id).
		Scan(&p.ID, &p.Title, &p.Description, &p.PriceCents, &p.Stock)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	_ = json.NewEncoder(w).Encode(p)
}
