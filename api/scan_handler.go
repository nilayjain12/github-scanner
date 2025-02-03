package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github-scanner/internal/models"
	"github-scanner/internal/services"
)

func ScanHandler(w http.ResponseWriter, r *http.Request) {
	var payload models.ScanRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("Error decoding payload: %s", err.Error())
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	results, err := services.ScanFiles(payload.Repo, payload.Files)
	if err != nil {
		http.Error(w, "Error scanning files", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
