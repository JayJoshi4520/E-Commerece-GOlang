package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	db  *pgxpool.Pool
	jwt []byte
}

type creds struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func loadENV() error {
	err := godotenv.Load()
	if err != nil {
		// Try loading from specific paths if the default fails
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

func random32() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return string(b)
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

	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}

	defer pool.Close()
	err = pool.Ping(context.Background())
	if err != nil {
		log.Fatalf("Unable to ping database: %v", err)
	}
	s := &Server{db: pool, jwt: jwtSecret}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Post("/v1/auth/register", s.register)
	r.Post("/v1/auth/login", s.login)
	r.With(s.authn).Get("/v1/auth/me", s.me)
	log.Println("auth listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", r))
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var c creds
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		http.Error(w, "Bad Json", 400)
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(c.Password), bcrypt.DefaultCost)
	_, err := s.db.Exec(r.Context(),
		"INSERT INTO users (email, password_hash) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING",
		c.Email, string(hash))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(201)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "registred"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var c creds
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		http.Error(w, "Bad Json", 400)
		return
	}
	var hash string
	err := s.db.QueryRow(r.Context(),
		"SELECT password_hash FROM users WHERE email=$1",
		c.Email).Scan(&hash)
	if err != nil {
		http.Error(w, "invalid credentials", 401)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(c.Password)) != nil {
		http.Error(w, "invalid credentials", 401)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": c.Email,
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	})
	t, _ := token.SignedString(s.jwt)
	_ = json.NewEncoder(w).Encode(map[string]string{"token": t})
}

func (s *Server) authn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if len(auth) < 8 || auth[:7] != "Bearer " {
			http.Error(w, "missing token", 401)
			return
		}
		tok, err := jwt.Parse(auth[7:], func(t *jwt.Token) (interface{}, error) { return s.jwt, nil })
		if err != nil || !tok.Valid {
			http.Error(w, "invalid token", 401)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
