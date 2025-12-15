package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/elastic/go-elasticsearch"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

type Server struct {
	es *elasticsearch.Client
}

type ESProduct struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	PriceCents  int    `json:"price_cents"`
	Category    string `json:"category"`
	ImageURL    string `json:"image_url"`
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

func main() {
	err := loadENV()
	if err != nil {
		log.Fatalf("error loading environment variables: %v", err)
	}

	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{
			"https://localhost:9200",
		},
	})

	if err != nil {
		log.Fatalf("Unable to Connect to ES: %v", err)
	}

	s := Server{
		es: es,
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Get("/v1/search/products", s.searchProducts)
	log.Println("search service on :8084")
	log.Fatal(http.ListenAndServe(":8084", r))
}

func (s *Server) searchProducts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	catagory := r.URL.Query().Get("catagory")
	minPrice := r.URL.Query().Get("min_price")
	maxPrice := r.URL.Query().Get("max_price")

	must := []map[string]any{}

	if q != "" {
		must = append(must, map[string]any{
			"multi_match": map[string]any{
				"query":  q,
				"fields": []string{"title^3", "description"},
			},
		})
	}

	if catagory != "" {
		must = append(must, map[string]any{
			"term": map[string]any{
				"category": catagory,
			},
		})
	}

	if minPrice != "" || maxPrice != "" {
		rangeFilter := map[string]any{
			"range": map[string]any{
				"price_cents": map[string]any{},
			},
		}

		if minPrice != "" {
			rangeFilter["range"].(map[string]any)["price_cents"].(map[string]any)["gte"] = minPrice
		}

		if maxPrice != "" {
			rangeFilter["range"].(map[string]any)["price_cents"].(map[string]any)["lte"] = maxPrice
		}

		must = append(must, rangeFilter)
	}

	query := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": must,
				"filter": []map[string]any{
					{
						"term": map[string]any{
							"is_active": true,
						},
					},
				},
			},
		},
	}

	body, _ := json.Marshal(query)
	res, err := s.es.Search(
		s.es.Search.WithIndex("products"),
		s.es.Search.WithBody(strings.NewReader(string(body))),
	)

	if err != nil {
		http.Error(w, err.Error(), 500)
	}

	defer res.Body.Close()

	var esResp map[string]any
	json.NewDecoder(res.Body).Decode(&esResp)

	hits := esResp["hits"].(map[string]any)["hits"].([]map[string]any)

	var outs []map[string]any
	for _, h := range hits {
		src := h["source"].(map[string]any)["_source"]
		outs = append(outs, src.(map[string]any))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(outs)
}
