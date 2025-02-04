// db.go
package database

import (
	"database/sql"
	"log"
	"os"

	"github-scanner/internal/models"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

// InitDB opens the database connection and executes the schema.
func InitDB() {
	var err error
	DB, err = sql.Open("sqlite3", os.Getenv("DB_PATH"))
	if err != nil {
		log.Fatalf("ERROR: Unable to open database: %v", err)
	}

	schemaPath := "internal/database/schema/vuln_scan_schema.sql"
	sqlSchema, err := os.ReadFile(schemaPath)
	if err != nil {
		log.Fatalf("ERROR: Unable to read schema file (%s): %v", schemaPath, err)
	}

	if _, err = DB.Exec(string(sqlSchema)); err != nil {
		log.Fatalf("ERROR: Failed to execute schema: %v", err)
	}
	log.Println("INFO: Database initialized successfully")
}

// StoreScanResults inserts a record into the scan_results table.
func StoreScanResults(scanID, timestamp, scanStatus, resourceType, resourceName string) error {
	_, err := DB.Exec(`
		INSERT OR REPLACE INTO scan_results (scan_id, timestamp, scan_status, resource_type, resource_name)
		VALUES (?, ?, ?, ?, ?)
	`, scanID, timestamp, scanStatus, resourceType, resourceName)
	if err != nil {
		log.Printf("ERROR: Failed to store scan result for scanID %s: %v", scanID, err)
	}
	return err
}

// StoreVulnerability inserts a record into the vulnerabilities table.
func StoreVulnerability(scanID, vulnID, severity string, cvss float64, status, packageName, currentVersion, fixedVersion, description, publishedDate, link string) error {
	_, err := DB.Exec(`
		INSERT OR REPLACE INTO vulnerabilities (id, scan_id, severity, cvss, status, package_name, current_version, fixed_version, description, published_date, link)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, vulnID, scanID, severity, cvss, status, packageName, currentVersion, fixedVersion, description, publishedDate, link)
	if err != nil {
		log.Printf("ERROR: Failed to store vulnerability %s for scanID %s: %v", vulnID, scanID, err)
	}
	return err
}

// StoreRiskFactor inserts a record into the risk_factors table.
func StoreRiskFactor(scanID, vulnID, riskFactor string) error {
	_, err := DB.Exec(`
		INSERT OR REPLACE INTO risk_factors (vulnerability_id, scan_id, risk_factor)
		VALUES (?, ?, ?)
	`, vulnID, scanID, riskFactor)
	if err != nil {
		log.Printf("ERROR: Failed to store risk factor for vulnerability %s in scanID %s: %v", vulnID, scanID, err)
	}
	return err
}

// StoreScanSummary inserts a record into the scan_summary table.
func StoreScanSummary(scanID string, totalVulns, critical, high, medium, low, fixable int, compliant bool) error {
	_, err := DB.Exec(`
		INSERT OR REPLACE INTO scan_summary (scan_id, total_vulnerabilities, critical_count, high_count, medium_count, low_count, fixable_count, compliant)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, scanID, totalVulns, critical, high, medium, low, fixable, compliant)
	if err != nil {
		log.Printf("ERROR: Failed to store scan summary for scanID %s: %v", scanID, err)
	}
	return err
}

// StoreScanMetadata inserts a record into the scan_metadata table.
func StoreScanMetadata(scanID, scannerVersion, policiesVersion string) error {
	_, err := DB.Exec(`
		INSERT OR REPLACE INTO scan_metadata (scan_id, scanner_version, policies_version)
		VALUES (?, ?, ?)
	`, scanID, scannerVersion, policiesVersion)
	if err != nil {
		log.Printf("ERROR: Failed to store scan metadata for scanID %s: %v", scanID, err)
	}
	return err
}

// StoreScanningRule inserts a scanning rule into the scanning_rules table.
func StoreScanningRule(scanID, rule string) error {
	_, err := DB.Exec(`
		INSERT OR REPLACE INTO scanning_rules (scan_id, rule)
		VALUES (?, ?)
	`, scanID, rule)
	if err != nil {
		log.Printf("ERROR: Failed to store scanning rule for scanID %s: %v", scanID, err)
	}
	return err
}

// StoreExcludedPath inserts an excluded path into the excluded_paths table.
func StoreExcludedPath(scanID, path string) error {
	_, err := DB.Exec(`
		INSERT OR REPLACE INTO excluded_paths (scan_id, path)
		VALUES (?, ?)
	`, scanID, path)
	if err != nil {
		log.Printf("ERROR: Failed to store excluded path for scanID %s: %v", scanID, err)
	}
	return err
}

// QueryPayloads returns rows from scan_results with at least one vulnerability matching the severity filter.
func QueryPayloads(filters map[string]interface{}) (*sql.Rows, error) {
	var query string
	var args []interface{}

	if severity, exists := filters["severity"].(string); exists && severity != "" {
		query = `
			SELECT DISTINCT sr.scan_id, sr.timestamp, sr.scan_status, sr.resource_type, sr.resource_name
			FROM scan_results sr
			JOIN vulnerabilities v ON sr.scan_id = v.scan_id
			WHERE v.severity = ?`
		args = append(args, severity)
	} else {
		query = `
			SELECT scan_id, timestamp, scan_status, resource_type, resource_name 
			FROM scan_results`
	}

	log.Printf("INFO: Executing query: %s", query)
	return DB.Query(query, args...)
}

// GetVulnerabilities retrieves all vulnerabilities (and their risk factors) for a given scan_id.
func GetVulnerabilities(scanID string) ([]models.Vulnerability, error) {
	rows, err := DB.Query(`
		SELECT id, severity, cvss, status, package_name, current_version, fixed_version, description, published_date, link 
		FROM vulnerabilities
		WHERE scan_id = ?`, scanID)
	if err != nil {
		log.Printf("ERROR: Querying vulnerabilities for scanID %s: %v", scanID, err)
		return nil, err
	}
	defer rows.Close()

	var vulns []models.Vulnerability
	for rows.Next() {
		var v models.Vulnerability
		if err := rows.Scan(&v.ID, &v.Severity, &v.CVSS, &v.Status, &v.PackageName, &v.CurrentVersion, &v.FixedVersion, &v.Description, &v.PublishedDate, &v.Link); err != nil {
			log.Printf("ERROR: Scanning vulnerability for scanID %s: %v", scanID, err)
			continue
		}
		// Retrieve risk factors.
		riskRows, err := DB.Query(`
			SELECT risk_factor 
			FROM risk_factors 
			WHERE scan_id = ? AND vulnerability_id = ?`, scanID, v.ID)
		if err == nil {
			var riskFactors []string
			for riskRows.Next() {
				var rf string
				if err := riskRows.Scan(&rf); err == nil {
					riskFactors = append(riskFactors, rf)
				}
			}
			riskRows.Close()
			v.RiskFactors = riskFactors
		} else {
			log.Printf("WARN: Unable to retrieve risk factors for vulnerability %s in scanID %s", v.ID, scanID)
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}

// GetScanSummary retrieves the scan summary for a given scan_id.
func GetScanSummary(scanID string) (*models.ScanSummary, error) {
	row := DB.QueryRow(`
		SELECT total_vulnerabilities, critical_count, high_count, medium_count, low_count, fixable_count, compliant 
		FROM scan_summary
		WHERE scan_id = ?`, scanID)

	var summary models.ScanSummary
	var critical, high, medium, low int

	if err := row.Scan(&summary.TotalVulnerabilities, &critical, &high, &medium, &low, &summary.FixableCount, &summary.Compliant); err != nil {
		log.Printf("ERROR: Retrieving scan summary for scanID %s: %v", scanID, err)
		return nil, err
	}

	summary.SeverityCounts = map[string]int{
		"CRITICAL": critical,
		"HIGH":     high,
		"MEDIUM":   medium,
		"LOW":      low,
	}

	return &summary, nil
}

// GetScanMetadata retrieves the scan metadata for a given scan_id.
func GetScanMetadata(scanID string) (*models.ScanMetadata, error) {
	row := DB.QueryRow(`
		SELECT scanner_version, policies_version 
		FROM scan_metadata
		WHERE scan_id = ?`, scanID)
	var metadata models.ScanMetadata
	if err := row.Scan(&metadata.ScannerVersion, &metadata.PoliciesVersion); err != nil {
		log.Printf("ERROR: Retrieving scan metadata for scanID %s: %v", scanID, err)
		return nil, err
	}

	// Retrieve scanning rules.
	rulesRows, err := DB.Query(`SELECT rule FROM scanning_rules WHERE scan_id = ?`, scanID)
	if err == nil {
		var rules []string
		for rulesRows.Next() {
			var rule string
			if err := rulesRows.Scan(&rule); err == nil {
				rules = append(rules, rule)
			}
		}
		rulesRows.Close()
		metadata.ScanningRules = rules
	} else {
		log.Printf("WARN: Retrieving scanning rules for scanID %s: %v", scanID, err)
	}

	// Retrieve excluded paths.
	pathsRows, err := DB.Query(`SELECT path FROM excluded_paths WHERE scan_id = ?`, scanID)
	if err == nil {
		var paths []string
		for pathsRows.Next() {
			var path string
			if err := pathsRows.Scan(&path); err == nil {
				paths = append(paths, path)
			}
		}
		pathsRows.Close()
		metadata.ExcludedPaths = paths
	} else {
		log.Printf("WARN: Retrieving excluded paths for scanID %s: %v", scanID, err)
	}
	return &metadata, nil
}

// QueryVulnerabilities returns rows from the vulnerabilities table matching the severity filter.
func QueryVulnerabilities(filters map[string]interface{}) (*sql.Rows, error) {
	var query string
	var args []interface{}

	if severity, exists := filters["severity"].(string); exists && severity != "" {
		query = `
			SELECT id, scan_id, severity, cvss, status, package_name, current_version, fixed_version, description, published_date, link 
			FROM vulnerabilities
			WHERE severity = ?`
		args = append(args, severity)
	} else {
		query = `
			SELECT id, scan_id, severity, cvss, status, package_name, current_version, fixed_version, description, published_date, link 
			FROM vulnerabilities`
	}
	log.Printf("INFO: Executing vulnerabilities query: %s", query)
	return DB.Query(query, args...)
}

// GetRiskFactors retrieves all risk factors for the given vulnerability.
func GetRiskFactors(scanID, vulnID string) ([]string, error) {
	rows, err := DB.Query(`
		SELECT risk_factor 
		FROM risk_factors 
		WHERE scan_id = ? AND vulnerability_id = ?`, scanID, vulnID)
	if err != nil {
		log.Printf("ERROR: Querying risk factors for vulnerability %s in scanID %s: %v", vulnID, scanID, err)
		return nil, err
	}
	defer rows.Close()

	var riskFactors []string
	for rows.Next() {
		var rf string
		if err := rows.Scan(&rf); err != nil {
			log.Printf("WARN: Scanning risk factor for vulnerability %s in scanID %s: %v", vulnID, scanID, err)
			continue
		}
		riskFactors = append(riskFactors, rf)
	}
	return riskFactors, nil
}
