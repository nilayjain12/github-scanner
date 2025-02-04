package test

import (
	"os"
	"testing"

	"github-scanner/internal/database"
)

func TestDatabaseStoreAndQuery(t *testing.T) {
	// Set up a temporary project structure with DB schema.
	cleanup := setupTempDB(t)
	defer cleanup()

	// Use an in‑memory database.
	os.Setenv("DB_PATH", ":memory:")
	database.InitDB()

	// Insert a scan result.
	err := database.StoreScanResults("scan1", "2021-01-01T00:00:00Z", "success", "repo", "example")
	if err != nil {
		t.Fatalf("StoreScanResults failed: %v", err)
	}

	// Insert a vulnerability.
	err = database.StoreVulnerability("scan1", "vuln1", "High", 7.5, "open", "pkg", "1.0", "1.1", "desc", "2021-01-01", "http://link")
	if err != nil {
		t.Fatalf("StoreVulnerability failed: %v", err)
	}

	// Insert a risk factor.
	err = database.StoreRiskFactor("scan1", "vuln1", "RF1")
	if err != nil {
		t.Fatalf("StoreRiskFactor failed: %v", err)
	}

	// Query scan_results without filters.
	rows, err := database.QueryPayloads(map[string]interface{}{})
	if err != nil {
		t.Fatalf("QueryPayloads failed: %v", err)
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		count++
	}
	if count != 1 {
		t.Fatalf("Expected 1 scan result, got %d", count)
	}

	// Test GetRiskFactors.
	rf, err := database.GetRiskFactors("scan1", "vuln1")
	if err != nil {
		t.Fatalf("GetRiskFactors failed: %v", err)
	}
	if len(rf) != 1 || rf[0] != "RF1" {
		t.Fatalf("Expected risk factor 'RF1', got %v", rf)
	}
}