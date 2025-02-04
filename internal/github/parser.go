// parser.go
package github

import (
	"encoding/json"

	"github-scanner/internal/models"
	"log"
)

// ParseJSON converts raw JSON content into a slice of ScanResults.
func ParseJSON(content []byte, file string) []models.ScanResults {
	var wrappers []models.ScanResultsWrapper
	err := json.Unmarshal(content, &wrappers)
	if err != nil {
		log.Printf("ERROR: Failed to unmarshal JSON from %s: %v", file, err)
		return []models.ScanResults{}
	}

	var scans []models.ScanResults
	for _, wrapper := range wrappers {
		scan := wrapper.ScanResults
		scan.SourceFile = file
		scans = append(scans, scan)
	}

	log.Printf("INFO: Parsed %d scan result(s) from file %s", len(scans), file)
	return scans
}
