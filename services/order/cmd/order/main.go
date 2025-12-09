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
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/segmentio/kafka-go"
)

type Server struct {
	db     *pgxpool.Pool
	jwtKey []byte
	kafka  *kafka.Writer
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

type CheckoutItem struct {
	ProductID string `json:"product_id"`
	Qty       int    `json:"qty"`
}
type CheckoutBody struct {
	Items []CheckoutItem `json:"items"`
}

type orderStatus struct {
	OrderID string `json:"order_id"`
	Status  string `json:"status"`
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

	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}
	defer pool.Close()

	writer := &kafka.Writer{
		Addr:         kafka.TCP(os.Getenv("KAFKA_BROKER")),
		Topic:        "order.created",
		Balancer:     &kafka.LeastBytes{},
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
		BatchSize:    1,
		RequiredAcks: kafka.RequireOne,
	}

	s := &Server{
		db:     pool,
		jwtKey: []byte(os.Getenv("JWT_SECRET")),
		kafka:  writer,
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Handle("/metrics", promhttp.Handler())
	r.With(s.authn).Post("/v1/orders/checkout", s.checkout)
	r.With(s.authn).Get("/v1/orders/{id}", s.getOrder)
	go s.consumePayments(context.Background())
	go s.consumePaymentFailures(context.Background())

	log.Println("catalog listening on :8083")
	log.Fatal(http.ListenAndServe(":8083", r))
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
			log.Printf("Token error: %v", err)
			http.Error(w, "invalid token", 401)
			return
		}
		claims, _ := tok.Claims.(jwt.MapClaims)
		email, _ := claims["sub"].(string)
		ctx := context.WithValue(r.Context(), "email", email)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) checkout(w http.ResponseWriter, r *http.Request) {
	email := r.Context().Value("email").(string)

	var body CheckoutBody
	var total int

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil || len(body.Items) == 0 {
		http.Error(w, "bad request", 400)
		return
	}

	transection, err := s.db.Begin(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	for _, it := range body.Items {
		var price int
		err := transection.QueryRow(
			r.Context(),
			"SELECT price_cents FROM products WHERE id=$1", it.ProductID).Scan(&price)
		if err != nil {
			http.Error(w, "product not found", 404)
			return
		}
		total += price * it.Qty
	}

	var orderID string

	err = transection.QueryRow(r.Context(),
		"INSERT INTO orders (user_email, status, total_cents) VALUES ($1, 'pending', $2) RETURNING id", email, total).Scan(&orderID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	for _, it := range body.Items {
		var price int
		_ = transection.QueryRow(r.Context(),
			"SELECT price_cents FROM products WHERE id=$1", it.ProductID).Scan(&price)
		_, err := transection.Exec(r.Context(),
			"INSERT INTO order_items (order_id, product_id, qty, price_cents) VALUES ($1, $2, $3, $4)",
			orderID, it.ProductID, it.Qty, price,
		)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}

	err = transection.Commit(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	event := map[string]any{
		"order_id":    orderID,
		"user_email":  email,
		"total_cents": total,
		"items":       body.Items,
		"created_at":  time.Now().UTC(),
	}
	payload, _ := json.Marshal(event)
	err = s.kafka.WriteMessages(r.Context(), kafka.Message{Value: payload})
	if err != nil {
		log.Println("kafka publish failed:", err)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"order_id":    orderID,
		"status":      "pending",
		"total_cents": total,
	})
}

func (s *Server) consumePayments(ctx context.Context) {
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers: []string{getenv("KAFKA_BROKER", "localhost:9092")},
		Topic:   "payment.succeeded",
		GroupID: "order-service",
	})
	defer r.Close()

	log.Println("order: consuming 'payment.succeeded'")
	for {
		m, err := r.ReadMessage(ctx)
		if err != nil {
			log.Fatalf("Reading Error: %v\n", err)
			continue
		}
		var event orderStatus
		err = json.Unmarshal(m.Value, &event)
		if err != nil {
			log.Fatalf("Bad Event: %v\n", err)
			continue
		}
		if event.Status != "succeeded" {
			continue
		}

		_, err = s.db.Exec(ctx,
			"UPDATE orders SET status='paid' WHERE id=$1",
			event.OrderID)
		if err != nil {
			log.Printf("Order update failed: %v", err)
		}
		log.Println("order marked paid:", event.OrderID)
	}
}


func (s *Server) consumePaymentFailures(ctx context.Context) {
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers: []string{getenv("KAFKA_BROKER", "localhost:9092")},
		Topic:   "payment.failed",
		GroupID: "order-service",
	})
	defer r.Close()

	log.Println("order: consuming 'payment.failed'")
	for {
		m, err := r.ReadMessage(ctx)
		if err != nil {
			log.Fatalf("Reading Error: %v\n", err)
			continue
		}
		var event orderStatus
		err = json.Unmarshal(m.Value, &event)
		if err != nil {
			log.Fatalf("Bad Event: %v\n", err)
			continue
		}
		if event.Status != "failed" {
			continue
		}

		_, err = s.db.Exec(ctx,
			"UPDATE orders SET status='failed' WHERE id=$1",
			event.OrderID)
		if err != nil {
			log.Printf("Order failed update: %v", err)
		}
	}
}



func (s *Server) getOrder(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var email, status string
	var total int
	err := s.db.QueryRow(r.Context(),
		"SELECT user_email, status, total_cents FROM orders WHERE id=$1", id).
		Scan(&email, &status, &total)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id": id, "user_email": email, "status": status, "total_cents": total,
	})
}
