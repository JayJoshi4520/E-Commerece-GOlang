package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
)

type Server struct {
	db        *pgxpool.Pool
	rdb       *redis.Client
	jwtKey    []byte
	assetsDir string
}

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

func random32() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

var rdb = redis.NewClient(&redis.Options{Addr: "localhost:6379"})

func main() {
	loadENV()

	dbURL := getenv("DATABASE_URL", "postgres://app:example@localhost:5432/app?sslmode=disable")
	jwtSecret := []byte(getenv("JWT_SECRET", random32()))
	assetsDir := getenv("ASSETS_DIR", "./assets")

	rdb := redis.NewClient(&redis.Options{
		Addr: getenv("REDIS_ADDR", "localhost:6379"),
	})

	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("Error Creating a Pool: %v", err)
	}
	defer pool.Close()

	s := &Server{
		db:        pool,
		rdb:       rdb,
		jwtKey:    jwtSecret,
		assetsDir: assetsDir,
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Handle("/metrics", promhttp.Handler())

	r.Get("/v1/products/list", s.list)
	r.Get("/v1/products/{id}", s.get)

	// seller endpoints
	r.With(s.authn, s.requireRole("seller")).Post("/v1/products", s.createProduct)
	r.With(s.authn, s.requireRole("seller")).Put("/v1/products/{id}", s.updateProduct)
	r.With(s.authn, s.requireRole("seller")).Delete("/v1/products/{id}", s.deleteProduct)
	r.With(s.authn, s.requireRole("seller")).Post("/v1/products/{id}/image", s.uploadProductImage)

	log.Println("catalog listening on :8082")
	log.Fatal(http.ListenAndServe(":8082", r))
}

func (s *Server) authn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if len(auth) < 8 || auth[:7] != "Bearer " {
			http.Error(w, "missing token", 401)
			return
		}
		tok, err := jwt.Parse(auth[7:], func(t *jwt.Token) (interface{}, error) { return s.jwtKey, nil })
		if err != nil || !tok.Valid {
			http.Error(w, "invalid token", 401)
			return
		}
		claims, _ := tok.Claims.(jwt.MapClaims)
		role := claims["role"].(string)
		email, _ := claims["sub"].(string)
		ctx := context.WithValue(r.Context(), "email", email)
		ctx = context.WithValue(ctx, "role", role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (S *Server) requireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Context().Value("role") != role {
				http.Error(w, "forbidden", 402)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
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

func (s *Server) createProduct(w http.ResponseWriter, r *http.Request) {
	var p P
	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		http.Error(w, "invalid json", 400)
	}

	err = s.db.QueryRow(r.Context(),
		`INSERT INTO products (title, description, price_cents, stock) VALUES ($1, $2, $3, $4) RETURNING id`,
		p.Title, p.Description, p.PriceCents, p.Stock).Scan(&p.ID)
	if err != nil {
		http.Error(w, err.Error(), 500)
	}

	s.rdb.Del(r.Context(), "catalog:products:list")
	json.NewEncoder(w).Encode(p)
}

func (s *Server) updateProduct(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var p P
	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		http.Error(w, "invalid json", 400)
		return
	}

	_, err = s.db.Exec(r.Context(),
		`UPDATE products SET title=$1, description=$2, price_cents=$3, stock=$4, updated_at=now() WHERE id=$5`,
		p.Title, p.Description, p.PriceCents, p.Stock, id)
	if err != nil {
		http.Error(w, err.Error(), 500)
	}

	s.rdb.Del(r.Context(), "catalog:products:list")
	s.rdb.Del(r.Context(), "catalog:product:"+id)

	w.WriteHeader(204)
}

func (s *Server) deleteProduct(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	_, err := s.db.Exec(r.Context(),
		"DELETE FROM products WHERE id=$1", id)

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	s.rdb.Del(r.Context(), "catalog:products:list")
	s.rdb.Del(r.Context(), "catalog:product:"+id)

	w.WriteHeader(204)
}

func (s *Server) uploadProductImage(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "file too large or invalid form", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("image")
	if err != nil {
		http.Error(w, "missing image field", http.StatusBadRequest)
		return
	}
	defer file.Close()
	buf := make([]byte, 512)
	n, _ := file.Read(buf)
	fileType := http.DetectContentType(buf[:n])

	_, err = file.Seek(0, 0)
	if err != nil {
		http.Error(w, "file not found", 500)
		return
	}
	if fileType != "image/jpeg" && fileType != "image/png" && fileType != "image/webp" {
		http.Error(w, "invalid image type", http.StatusBadRequest)
		return
	}
	extension := filepath.Ext(header.Filename)
	if extension == "" {
		exts, _ := mime.ExtensionsByType(fileType)
		if len(exts) > 0 {
			extension = exts[0]
		} else {
			extension = ".jpg"
		}
	}

	filename := fmt.Sprintf("%s_%d%s", id, time.Now().Unix(), extension)
	relPath := filepath.Join("products", filename)
	absPath := filepath.Join(s.assetsDir, relPath)
	err = os.MkdirAll(filepath.Dir(absPath), 0o755)
	if err != nil {
		http.Error(w, "unable to create dir", http.StatusInternalServerError)
		return
	}

	dst, err := os.Create(absPath)
	if err != nil {
		http.Error(w, "unable to create file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(w, "unable to copy file", http.StatusInternalServerError)
		return
	}
	imageURL := "/static/" + filepath.ToSlash(relPath)
	_, err = s.db.Exec(r.Context(),
		"UPDATE products SET image_url=$1, updated_at=now() WHERE id=$2",
		imageURL, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.rdb.Del(r.Context(), "catalog:products:list")
	s.rdb.Del(r.Context(), "catalog:product:"+id)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"image_url": imageURL,
	})
}
