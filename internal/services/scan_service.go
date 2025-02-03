package services

import (
	"strings"
	"sync"

	"github-scanner/internal/database"
	"github-scanner/internal/github"
	"github-scanner/internal/models"
)

func ScanFiles(repo string, files []string) ([]models.ScanResults, error) {
	var (
		results []models.ScanResults
		mu      sync.Mutex                     // Protects access to results
		wg      sync.WaitGroup                 // WaitGroup for concurrent processing
		sem     = make(chan struct{}, 3)       // Limit to 3 concurrent file processing
		errChan = make(chan error, len(files)) // Buffer errors per file
	)

	for _, file := range files {
		// Only process JSON files.
		if !strings.HasSuffix(file, ".json") {
			continue
		}

		wg.Add(1)
		sem <- struct{}{} // Acquire a slot for concurrency

		go func(file string) {
			defer wg.Done()
			defer func() { <-sem }() // Release slot when done

			// Fetch file content.
			content, err := github.FetchFile(repo, file)
			if err != nil {
				errChan <- err
				return
			}

			// Parse the fetched JSON content as an array of ScanResults.
			scans := github.ParseJSON(content, file)
			if len(scans) == 0 {
				return // Nothing parsed; skip.
			}

			// Process each scan result in the file.
			for _, parsed := range scans {
				// Store scan results into the scan_results table.
				err = database.StoreScanResults(parsed.ScanID, parsed.ScanTime, parsed.Status, parsed.ResourceType, parsed.ResourceName)
				if err != nil {
					errChan <- err
					return
				}

				// Process vulnerabilities and their risk factors.
				for _, vulnerability := range parsed.Vulnerabilities {
					err = database.StoreVulnerability(parsed.ScanID, vulnerability.ID, vulnerability.Severity, vulnerability.CVSS, vulnerability.Status,
						vulnerability.PackageName, vulnerability.CurrentVersion, vulnerability.FixedVersion, vulnerability.Description, vulnerability.PublishedDate, vulnerability.Link)
					if err != nil {
						errChan <- err
						return
					}

					// Insert each risk factor.
					for _, rf := range vulnerability.RiskFactors {
						err = database.StoreRiskFactor(parsed.ScanID, vulnerability.ID, rf)
						if err != nil {
							errChan <- err
							return
						}
					}
				}

				// Store scan summary if available.
				if parsed.Summary != nil {
					// Extract severity counts from the map.
					critical := parsed.Summary.SeverityCounts["Critical"]
					high := parsed.Summary.SeverityCounts["High"]
					medium := parsed.Summary.SeverityCounts["Medium"]
					low := parsed.Summary.SeverityCounts["Low"]

					err = database.StoreScanSummary(parsed.ScanID, parsed.Summary.TotalVulnerabilities, critical, high, medium, low, parsed.Summary.FixableCount, parsed.Summary.Compliant)
					if err != nil {
						errChan <- err
						return
					}
				}

				// Store scan metadata, scanning rules, and excluded paths if available.
				if parsed.Metadata != nil {
					err = database.StoreScanMetadata(parsed.ScanID, parsed.Metadata.ScannerVersion, parsed.Metadata.PoliciesVersion)
					if err != nil {
						errChan <- err
						return
					}

					// Insert scanning rules.
					for _, rule := range parsed.Metadata.ScanningRules {
						err = database.StoreScanningRule(parsed.ScanID, rule)
						if err != nil {
							errChan <- err
							return
						}
					}

					// Insert excluded paths.
					for _, path := range parsed.Metadata.ExcludedPaths {
						err = database.StoreExcludedPath(parsed.ScanID, path)
						if err != nil {
							errChan <- err
							return
						}
					}
				}

				// Append the processed scan result to the results slice.
				mu.Lock()
				results = append(results, parsed)
				mu.Unlock()
			}
		}(file)
	}

	wg.Wait()
	close(errChan)

	// If any error occurred in any goroutine, return the first one.
	for err := range errChan {
		if err != nil {
			return nil, err
		}
	}

	return results, nil
}
