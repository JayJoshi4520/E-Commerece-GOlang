package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/segmentio/kafka-go"
)

type orderCreated struct {
	OrderID    string `json:"order_id"`
	UserEmail  string `json:"user_email"`
	TotalCents int    `json:"total_cents"`
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

func createTopic(broker, topic string) error {
	log.Printf("Attempting to create topic: %s on broker: %s\n", topic, broker)
	conn, err := kafka.DialContext(context.Background(), "tcp", broker)
	if err != nil {
		return fmt.Errorf("failed to dial broker for admin: %w", err)
	}
	defer conn.Close()

	topicConfig := kafka.TopicConfig{
		Topic:             topic,
		NumPartitions:     1,
		ReplicationFactor: 1,
	}
	err = conn.CreateTopics(topicConfig)
	if err != nil {
		if err.Error() == "topic already exists" {
			log.Printf("Topic %s already exists. Continuing...\n", topic)
			return nil
		}
		return fmt.Errorf("failed to create topic %s: %w", topic, err)
	}
	log.Printf("Successfully created topic: %s\n", topic)
	return nil
}

func main() {
	err := loadENV()
	if err != nil {
		log.Printf("Warning: %v\n", err)
		log.Println("Continuing with system environment variables...")
	}

	dbURL := getenv("DATABASE_URL", "postgres://app:example@localhost:5432/app?sslmode=disable")
	if dbURL == "" {
		log.Fatal("DATABASE_URL enviroment variable is not set.")
	}

	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}
	defer pool.Close()

	broker := getenv("KAFKA_BROKER", "localhost:29092")

	if broker == "" {
		log.Fatal("KAFKA_BROKER environmental veriable is not set.")
	}

	if err := createTopic(broker, "payment.succeeded"); err != nil {
		log.Fatalf("Failed to initialize producer topic 'payment.succeeded': %v", err)
	}

	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers: []string{broker},
		Topic:   "order.created",
		GroupID: "payment-service",
	})

	defer r.Close()

	writer := &kafka.Writer{
		Addr:     kafka.TCP(broker),
		Topic:    "payment.succeeded",
		Balancer: &kafka.LeastBytes{},
	}

	defer writer.Close()

	log.Println("Payment service is listening to 'order.created'")

	for {
		m, err := r.ReadMessage(context.Background())
		if err != nil {
			log.Fatalf("Reading Error: %v\n", err)
		}
		var event orderCreated
		err = json.Unmarshal(m.Value, &event)
		if err != nil {
			log.Fatalf("Bad Event: %v\n", err)
			continue
		}

		log.Println("processing payment for order:", event.OrderID, "total:", event.TotalCents)
		time.Sleep(800 * time.Millisecond)
		payload, _ := json.Marshal(map[string]any{
			"order_id": event.OrderID,
			"status":   "succeeded",
			"provider": "mock",
			"paid_at":  time.Now().UTC(),
		})
		err = writer.WriteMessages(context.Background(), kafka.Message{Value: payload})
		if err != nil {
			log.Printf("Write Payment event failed: %v", err)
		}
	}
}
