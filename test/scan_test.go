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

func TestScanHandler(t *testing.T) {
	payload := models.ScanRequestPayload{
		Repo:  "https://github.com/example/repo",
		Files: []string{"test.json"},
	}

	body, _ := json.Marshal(payload)
	r := httptest.NewRequest("POST", "/scan", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	api.ScanHandler(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status OK, got %v", w.Code)
	}
}