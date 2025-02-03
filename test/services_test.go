package test

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github-scanner/internal/database"
	"github-scanner/internal/models"
	"github-scanner/internal/services"
)

func TestScanFiles(t *testing.T) {
	// Set up a temporary DB environment.
	cleanup := setupTempDB(t)
	defer cleanup()

	// Use an in‑memory database.
	os.Setenv("DB_PATH", ":memory:")
	database.InitDB()

	// Create a temporary directory to act as the "repo" (local source).
	tmpDir, err := ioutil.TempDir("", "repo")
	if err != nil {
		t.Fatalf("Failed to create temp repo dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test JSON file (only process .json files).
	testJSONPath := filepath.Join(tmpDir, "test.json")
	jsonContent := `
	[
		{
			"scanResults": {
				"scan_id": "scan_test",
				"timestamp": "2021-01-01T00:00:00Z",
				"scan_status": "success",
				"resource_type": "repo",
				"resource_name": "example",
				"vulnerabilities": [
					{
						"id": "v1",
						"severity": "High",
						"cvss": 7.0,
						"status": "open",
						"package_name": "pkg1",
						"current_version": "1.0",
						"fixed_version": "1.1",
						"description": "desc",
						"published_date": "2021-01-01",
						"link": "http://link",
						"risk_factors": ["RF1"]
					}
				],
				"summary": {
					"total_vulnerabilities": 1,
					"severity_counts": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0},
					"fixable_count": 0,
					"compliant": true
				},
				"scan_metadata": {
					"scanner_version": "1.0",
					"policies_version": "1.0",
					"scanning_rules": ["rule1"],
					"excluded_paths": ["/tmp"]
				}
			}
		}
	]
	`
	err = ioutil.WriteFile(testJSONPath, []byte(jsonContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test JSON file: %v", err)
	}

	// Call ScanFiles with the temporary directory as the repo.
	results, err := services.ScanFiles(tmpDir, []string{"test.json"})
	if err != nil {
		t.Fatalf("ScanFiles returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 scan result, got %d", len(results))
	}
	if results[0].ScanID != "scan_test" {
		t.Fatalf("Expected scan_id 'scan_test', got %s", results[0].ScanID)
	}

	// Optionally, decode the returned JSON to ensure proper structure.
	out, _ := json.Marshal(results)
	t.Logf("ScanFiles output: %s", out)
}

func TestQueryBySeverity(t *testing.T) {
	// Set up a temporary DB environment.
	cleanup := setupTempDB(t)
	defer cleanup()

	// Use an in‑memory database.
	os.Setenv("DB_PATH", ":memory:")
	database.InitDB()

	// Insert a vulnerability using the database functions.
	err := database.StoreScanResults("scan_query", "2021-01-01T00:00:00Z", "success", "repo", "example")
	if err != nil {
		t.Fatalf("StoreScanResults failed: %v", err)
	}
	err = database.StoreVulnerability("scan_query", "v_query", "High", 8.0, "open", "pkg_query", "1.0", "1.1", "desc", "2021-01-01", "http://link")
	if err != nil {
		t.Fatalf("StoreVulnerability failed: %v", err)
	}
	err = database.StoreRiskFactor("scan_query", "v_query", "RFQ")
	if err != nil {
		t.Fatalf("StoreRiskFactor failed: %v", err)
	}

	// Create a query payload with severity "High".
	queryPayload := models.QueryRequestPayload{}
	queryPayload.Filters.Severity = "High"
	vulns, err := services.QueryBySeverity(queryPayload)
	if err != nil {
		t.Fatalf("QueryBySeverity returned error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("Expected 1 vulnerability, got %d", len(vulns))
	}
	if vulns[0].ID != "v_query" {
		t.Fatalf("Expected vulnerability ID 'v_query', got %s", vulns[0].ID)
	}
}
