package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github-scanner/internal/models"
	"github-scanner/internal/services"
)

func ScanHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure the method is POST.
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload models.ScanRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("Error decoding payload: %s", err.Error())
		http.Error(w, "Bad Request: Invalid request payload", http.StatusBadRequest)
		return
	}

	results, err := services.ScanFiles(payload.Repo, payload.Files)
	if err != nil {
		http.Error(w, "Internal Server Error: Error scanning files", http.StatusInternalServerError)
		return
	}

	// If no scans were processed, return 204 No Content.
	if len(results) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// Return 201 Created since resources were stored.
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(results); err != nil {
		log.Printf("Failed to encode scan results: %s", err.Error())
		http.Error(w, "Internal Server Error: Failed to encode response", http.StatusInternalServerError)
	}
}
