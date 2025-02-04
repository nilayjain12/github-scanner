// query_service.go
package services

import (
	"log"

	"github-scanner/internal/database"
	"github-scanner/internal/models"
)

// QueryBySeverity returns Vulnerability records matching the provided severity.
func QueryBySeverity(query models.QueryRequestPayload) ([]models.Vulnerability, error) {
	filters := make(map[string]interface{})
	if query.Filters.Severity != "" {
		filters["severity"] = query.Filters.Severity
	}

	rows, err := database.QueryVulnerabilities(filters)
	if err != nil {
		log.Printf("ERROR: Executing vulnerability query: %v", err)
		return nil, err
	}
	defer rows.Close()

	var vulnerabilities []models.Vulnerability
	for rows.Next() {
		var v models.Vulnerability
		var scanID string
		if err := rows.Scan(&v.ID, &scanID, &v.Severity, &v.CVSS, &v.Status, &v.PackageName, &v.CurrentVersion, &v.FixedVersion, &v.Description, &v.PublishedDate, &v.Link); err != nil {
			log.Printf("ERROR: Scanning vulnerability row: %v", err)
			continue
		}

		riskFactors, err := database.GetRiskFactors(scanID, v.ID)
		if err != nil {
			log.Printf("WARN: Retrieving risk factors for vulnerability %s: %v", v.ID, err)
		} else {
			v.RiskFactors = riskFactors
		}

		vulnerabilities = append(vulnerabilities, v)
	}
	log.Printf("INFO: QueryBySeverity retrieved %d vulnerability(ies)", len(vulnerabilities))
	return vulnerabilities, nil
}
