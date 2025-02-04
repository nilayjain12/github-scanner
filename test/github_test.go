package test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github-scanner/internal/github"
)

func TestFetchFileLocal(t *testing.T) {
	// Create a temporary directory and file.
	tmpDir, err := ioutil.TempDir("", "fetchfile")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFileName := "test.txt"
	expectedContent := "Hello, world!"
	err = ioutil.WriteFile(filepath.Join(tmpDir, testFileName), []byte(expectedContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	content, err := github.FetchFile(tmpDir, testFileName)
	if err != nil {
		t.Fatalf("FetchFile returned error: %v", err)
	}
	if string(content) != expectedContent {
		t.Fatalf("Expected content %s, got %s", expectedContent, string(content))
	}
}

func TestParseJSON(t *testing.T) {
	// Create valid JSON content representing an array of ScanResultsWrapper.
	jsonContent := `
	[
		{
			"scanResults": {
				"scan_id": "123",
				"timestamp": "2021-01-01T00:00:00Z",
				"scan_status": "success",
				"resource_type": "repo",
				"resource_name": "example",
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
	scans := github.ParseJSON([]byte(jsonContent), "test.json")
	if len(scans) != 1 {
		t.Fatalf("Expected 1 scan result, got %d", len(scans))
	}
	if scans[0].ScanID != "123" {
		t.Fatalf("Expected ScanID '123', got %s", scans[0].ScanID)
	}
}