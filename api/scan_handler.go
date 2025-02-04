// scan_handler.go
package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github-scanner/internal/models"
	"github-scanner/internal/services"
)

// ScanHandler processes /scan POST requests.
func ScanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logErrorAndRespond(w, "Method Not Allowed on /scan endpoint", http.StatusMethodNotAllowed)
		return
	}

	var payload models.ScanRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		logErrorAndRespond(w, "Invalid scan request payload", http.StatusBadRequest)
		return
	}

	logInfo("Starting scan for repository: %s", payload.Repo)
	results, err := services.ScanFiles(payload.Repo, payload.Files)
	if err != nil {
		logError("Error scanning files: %v", err)
		http.Error(w, "Internal Server Error: Error scanning files", http.StatusInternalServerError)
		return
	}

	if len(results) == 0 {
		logInfo("Scan completed with no results")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(results); err != nil {
		logErrorAndRespond(w, "Failed to encode scan response", http.StatusInternalServerError)
		return
	}
	logInfo("Scan completed successfully for repository: %s", payload.Repo)
}

// logInfo logs informational messages.
func logInfo(format string, v ...interface{}) {
	log.Printf("INFO: "+format, v...)
}

// logError logs error messages.
func logError(format string, v ...interface{}) {
	log.Printf("ERROR: "+format, v...)
}

// logErrorAndRespond logs an error and sends an HTTP error response.
func logErrorAndRespond(w http.ResponseWriter, msg string, code int) {
	log.Printf("ERROR: %s", msg)
	http.Error(w, msg, code)
}
