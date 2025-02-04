package test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

// setupTempDB creates a temporary directory with a mimicked project structure
// that contains the database schema file. It changes the working directory to that
// temporary directory so that database.InitDB (which expects a relative path) finds the schema.
// It returns a cleanup function to revert the working directory and remove the temp directory.
func setupTempDB(t *testing.T) func() {
	tempDir, err := ioutil.TempDir("", "testdb")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create the required folder structure: internal/database/schema/
	schemaDir := filepath.Join(tempDir, "internal", "database", "schema")
	err = os.MkdirAll(schemaDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create schema directory: %v", err)
	}

	// Write the schema file.
	schemaContent := `
	CREATE TABLE IF NOT EXISTS scan_results (
		scan_id TEXT PRIMARY KEY,
		timestamp TEXT,
		scan_status TEXT,
		resource_type TEXT,
		resource_name TEXT
	);
	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT PRIMARY KEY,
		scan_id TEXT,
		severity TEXT,
		cvss REAL,
		status TEXT,
		package_name TEXT,
		current_version TEXT,
		fixed_version TEXT,
		description TEXT,
		published_date TEXT,
		link TEXT
	);
	CREATE TABLE IF NOT EXISTS risk_factors (
		vulnerability_id TEXT,
		scan_id TEXT,
		risk_factor TEXT,
		PRIMARY KEY (vulnerability_id, scan_id, risk_factor)
	);
	CREATE TABLE IF NOT EXISTS scan_summary (
		scan_id TEXT PRIMARY KEY,
		total_vulnerabilities INTEGER,
		critical_count INTEGER,
		high_count INTEGER,
		medium_count INTEGER,
		low_count INTEGER,
		fixable_count INTEGER,
		compliant BOOLEAN
	);
	CREATE TABLE IF NOT EXISTS scan_metadata (
		scan_id TEXT PRIMARY KEY,
		scanner_version TEXT,
		policies_version TEXT
	);
	CREATE TABLE IF NOT EXISTS scanning_rules (
		scan_id TEXT,
		rule TEXT,
		PRIMARY KEY (scan_id, rule)
	);
	CREATE TABLE IF NOT EXISTS excluded_paths (
		scan_id TEXT,
		path TEXT,
		PRIMARY KEY (scan_id, path)
	);
	`
	schemaPath := filepath.Join(schemaDir, "vuln_scan_schema.sql")
	err = ioutil.WriteFile(schemaPath, []byte(schemaContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write schema file: %v", err)
	}

	// Save the old working directory.
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}

	// Change the working directory to tempDir.
	err = os.Chdir(tempDir)
	if err != nil {
		t.Fatalf("Failed to change working directory: %v", err)
	}

	// Return a cleanup function.
	return func() {
		_ = os.Chdir(oldDir)
		_ = os.RemoveAll(tempDir)
	}
}