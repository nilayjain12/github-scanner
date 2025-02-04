package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github-scanner/internal/models"
	"github-scanner/internal/services"
)

func QueryHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure the method is POST.
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Println("Received request on /query endpoint")
	var query models.QueryRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
		log.Println("Invalid query payload:", err)
		http.Error(w, "Bad Request: Invalid query payload", http.StatusBadRequest)
		return
	}

	// Get the list of vulnerabilities matching the filter.
	vulnerabilities, err := services.QueryBySeverity(query)
	if err != nil {
		log.Println("Query failed:", err)
		http.Error(w, "Internal Server Error: Query failed", http.StatusInternalServerError)
		return
	}

	// If there are no vulnerabilities matching the query, return 204 No Content.
	if len(vulnerabilities) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(vulnerabilities); err != nil {
		log.Println("Failed to encode response:", err)
		http.Error(w, "Internal Server Error: Failed to encode response", http.StatusInternalServerError)
		return
	}
	log.Println("Query executed successfully with severity filter:", query.Filters.Severity)
}
