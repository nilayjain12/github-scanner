package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github-scanner/api"
	"github-scanner/internal/models"
)

func TestQueryHandler(t *testing.T) {
	query := models.QueryRequestPayload{}
	query.Filters.Severity = "high"

	body, _ := json.Marshal(query)
	r := httptest.NewRequest("POST", "/query", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	api.QueryHandler(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status OK, got %v", w.Code)
	}
}
