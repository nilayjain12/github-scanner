// query_handler.go
package api

import (
	"encoding/json"
	"net/http"

	"github-scanner/internal/models"
	"github-scanner/internal/services"
)

// QueryHandler processes /query POST requests.
func QueryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logErrorAndRespond(w, "Method Not Allowed on /query endpoint", http.StatusMethodNotAllowed)
		return
	}

	logInfo("Processing /query request")
	var query models.QueryRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
		logErrorAndRespond(w, "Invalid query payload", http.StatusBadRequest)
		return
	}

	vulnerabilities, err := services.QueryBySeverity(query)
	if err != nil {
		logError("Query processing error: %v", err)
		http.Error(w, "Internal Server Error: Query failed", http.StatusInternalServerError)
		return
	}

	if len(vulnerabilities) == 0 {
		logInfo("No vulnerabilities found matching the query filter")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(vulnerabilities); err != nil {
		logErrorAndRespond(w, "Failed to encode query response", http.StatusInternalServerError)
		return
	}

	logInfo("Query executed successfully with filter: %s", query.Filters.Severity)
}



// logErrorAndRespond logs an error and sends an HTTP error response.
