// main.go
package main

import (
	"log"
	"net/http"
	"strings"
	"time"

	_ "github-scanner/docs" // This is important for swag to find your docs!

	"github-scanner/api"
	"github-scanner/config"
	"github-scanner/internal/database"

	"github.com/gorilla/mux"
	httpSwagger "github.com/swaggo/http-swagger"
)

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name X-API-KEY
func main() {
	// Load configuration and initialize the database.
	config.LoadConfig()
	database.InitDB()

	// Create a new router.
	router := mux.NewRouter()

	// Attach custom middleware.
	router.Use(rateLimitMiddleware)
	router.Use(authMiddleware)
	router.Use(recoverMiddleware)

	// Define endpoints.
	router.HandleFunc("/scan", api.ScanHandler).Methods("POST")
	router.HandleFunc("/query", api.QueryHandler).Methods("POST")

	// Health endpoint (used by Docker healthcheck)
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}).Methods("GET")

	// Swagger endpoint.
	router.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)

	// Custom 404 handler.
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	// Create a custom HTTP server with timeouts.
	server := &http.Server{
		Handler:      router,
		Addr:         ":8080",
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Println("INFO: Server is starting on port 8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("ERROR: Server terminated unexpectedly: %v", err)
	}
}

// authMiddleware enforces that requests include a valid API key.
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bypass API key check for Swagger docs.
		if strings.HasPrefix(r.URL.Path, "/swagger/") {
			next.ServeHTTP(w, r)
			return
		}

		apiKey := r.Header.Get("X-API-KEY")
		if apiKey == "" {
			log.Println("WARN: Request missing API key")
			http.Error(w, "Unauthorized: API key required", http.StatusUnauthorized)
			return
		}
		// In this example, the valid API key is "secret".
		if apiKey != "secret" {
			log.Printf("WARN: Request with invalid API key: %s", apiKey)
			http.Error(w, "Forbidden: Invalid API key", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware limits the number of concurrent requests.
func rateLimitMiddleware(next http.Handler) http.Handler {
	// Allow up to 5 concurrent requests.
	sem := make(chan struct{}, 5)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			next.ServeHTTP(w, r)
		default:
			log.Println("WARN: Too many concurrent requests")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		}
	})
}

// recoverMiddleware catches panics and returns a 500 Internal Server Error.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("ERROR: Panic recovered: %v", rec)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
