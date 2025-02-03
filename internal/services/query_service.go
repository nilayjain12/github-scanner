package services

import (
	"log"
	"github-scanner/internal/database"
	"github-scanner/internal/models"
)

// QueryBySeverity accepts a QueryRequestPayload object and returns a slice of Vulnerability
// objects that match the provided severity.
func QueryBySeverity(query models.QueryRequestPayload) ([]models.Vulnerability, error) {
	// Build filters from the query.
	filters := make(map[string]interface{})
	if query.Filters.Severity != "" {
		filters["severity"] = query.Filters.Severity
	}

	// Execute the query that returns vulnerability records.
	rows, err := database.QueryVulnerabilities(filters)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulnerabilities []models.Vulnerability
	for rows.Next() {
		var v models.Vulnerability
		var scanID string
		// Scan the row. Note that we also retrieve scan_id to use for fetching risk factors.
		err := rows.Scan(&v.ID, &scanID, &v.Severity, &v.CVSS, &v.Status, &v.PackageName, &v.CurrentVersion, &v.FixedVersion, &v.Description, &v.PublishedDate, &v.Link)
		if err != nil {
			log.Println("Error scanning vulnerability row:", err)
			continue
		}

		// Retrieve and set risk factors.
		rf, err := database.GetRiskFactors(scanID, v.ID)
		if err != nil {
			log.Printf("Error retrieving risk factors for vulnerability %s: %v", v.ID, err)
		} else {
			v.RiskFactors = rf
		}

		vulnerabilities = append(vulnerabilities, v)
	}
	return vulnerabilities, nil
}