// main.go
package main

import (
	"fmt"
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

// @title GitHub Scanner API
// @version 1.0
// @description API for scanning GitHub repositories and querying vulnerabilities.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.example.com/support
// @contact.email support@example.com

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name X-API-KEY
func main() {
	// Load configuration and initialize the DB.
	config.LoadConfig()
	database.InitDB()

	// Create a new router.
	r := mux.NewRouter()

	// Attach our custom middleware:
	r.Use(rateLimitMiddleware)
	r.Use(authMiddleware)
	r.Use(recoverMiddleware)

	// Define endpoints.
	r.HandleFunc("/scan", api.ScanHandler).Methods("POST")
	r.HandleFunc("/query", api.QueryHandler).Methods("POST")

	// Health endpoint (used by Docker healthcheck)
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")

	// Swagger endpoint.
	r.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)

	// Optionally set a custom NotFound handler for 404 responses.
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	// Use a custom HTTP server with timeouts.
	server := &http.Server{
		Handler:      r,
		Addr:         ":8080",
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	fmt.Println("Server running on port 8080")
	log.Fatal(server.ListenAndServe())
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
			http.Error(w, "Unauthorized: API key required", http.StatusUnauthorized)
			return
		}
		// In this example, the valid API key is "secret".
		if apiKey != "secret" {
			http.Error(w, "Forbidden: Invalid API key", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware limits the number of concurrent requests.
func rateLimitMiddleware(next http.Handler) http.Handler {
	// For this example, allow up to 5 concurrent requests.
	sem := make(chan struct{}, 5)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		}
	})
}

// recoverMiddleware catches panics and returns a 500 Internal Server Error.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
