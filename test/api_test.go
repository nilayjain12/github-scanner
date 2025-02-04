package test

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github-scanner/api"
	"github-scanner/internal/database"
	"github-scanner/internal/models"
)

func TestScanHandlerAPI(t *testing.T) {
	// Set up a temporary DB environment.
	cleanup := setupTempDB(t)
	defer cleanup()

	// Use an in‑memory database.
	os.Setenv("DB_PATH", ":memory:")
	database.InitDB()

	// Create a temporary repo directory with a JSON scan file.
	tmpDir, err := ioutil.TempDir("", "api_repo")
	if err != nil {
		t.Fatalf("Failed to create temp repo dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testJSONPath := filepath.Join(tmpDir, "test.json")
	jsonContent := `
	[
		{
			"scanResults": {
				"scan_id": "api_scan",
				"timestamp": "2021-01-01T00:00:00Z",
				"scan_status": "success",
				"resource_type": "repo",
				"resource_name": "api_example",
				"vulnerabilities": [],
				"summary": {
					"total_vulnerabilities": 0,
					"severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
					"fixable_count": 0,
					"compliant": true
				},
				"scan_metadata": {
					"scanner_version": "1.0",
					"policies_version": "1.0",
					"scanning_rules": [],
					"excluded_paths": []
				}
			}
		}
	]
	`
	err = ioutil.WriteFile(testJSONPath, []byte(jsonContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test JSON file: %v", err)
	}

	// Build payload for the scan handler.
	payload := models.ScanRequestPayload{
		Repo:  tmpDir, // use the local directory as the repo source
		Files: []string{"test.json"},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}
	req := httptest.NewRequest("POST", "/scan", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	api.ScanHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected status OK, got %v", w.Code)
	}

	// Check that the returned JSON contains our scan_id.
	var scans []models.ScanResults
	if err := json.NewDecoder(w.Body).Decode(&scans); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if len(scans) != 1 || scans[0].ScanID != "api_scan" {
		t.Fatalf("Unexpected scan result: %+v", scans)
	}
}

func TestQueryHandlerAPI(t *testing.T) {
	// Set up a temporary DB environment.
	cleanup := setupTempDB(t)
	defer cleanup()

	// Use an in‑memory database.
	os.Setenv("DB_PATH", ":memory:")
	database.InitDB()

	// Insert a vulnerability to later query.
	err := database.StoreScanResults("scan_api", "2021-01-01T00:00:00Z", "success", "repo", "api_example")
	if err != nil {
		t.Fatalf("StoreScanResults failed: %v", err)
	}
	err = database.StoreVulnerability("scan_api", "v_api", "High", 8.5, "open", "pkg_api", "1.0", "1.1", "desc", "2021-01-01", "http://link")
	if err != nil {
		t.Fatalf("StoreVulnerability failed: %v", err)
	}
	err = database.StoreRiskFactor("scan_api", "v_api", "RFA")
	if err != nil {
		t.Fatalf("StoreRiskFactor failed: %v", err)
	}

	// Build query payload for the query handler.
	queryPayload := models.QueryRequestPayload{}
	queryPayload.Filters.Severity = "High"
	body, err := json.Marshal(queryPayload)
	if err != nil {
		t.Fatalf("Failed to marshal query payload: %v", err)
	}
	req := httptest.NewRequest("POST", "/query", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	api.QueryHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected status OK, got %v", w.Code)
	}

	// Check that the returned vulnerabilities contain our inserted record.
	var vulns []models.Vulnerability
	if err := json.NewDecoder(w.Body).Decode(&vulns); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if len(vulns) != 1 || vulns[0].ID != "v_api" {
		t.Fatalf("Unexpected vulnerability result: %+v", vulns)
	}
}