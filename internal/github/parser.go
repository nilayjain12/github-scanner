package github

import (
	"encoding/json"
	"log"
	"github-scanner/internal/models"
)

// ParseJSON converts the raw JSON content (an array of wrappers) into a slice of ScanResults.
func ParseJSON(content []byte, file string) []models.ScanResults {
	var wrappers []models.ScanResultsWrapper
	err := json.Unmarshal(content, &wrappers)
	log.Printf("%v", wrappers)
	if err != nil {
		log.Printf("Error unmarshaling JSON content from %s: %v", file, err)
		// Return an empty slice if there's an error.
		return []models.ScanResults{}
	}

	// Extract the ScanResults from the wrappers.
	var scans []models.ScanResults
	for _, wrapper := range wrappers {
		scan := wrapper.ScanResults
		scan.SourceFile = file
		scans = append(scans, scan)
	}

	log.Printf("%+v", scans)
	return scans
}
