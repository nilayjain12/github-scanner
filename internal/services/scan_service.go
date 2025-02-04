// scan_service.go
package services

import (
	"strings"
	"sync"

	"github-scanner/internal/database"
	"github-scanner/internal/github"
	"github-scanner/internal/models"
	"log"
)

// ScanFiles processes the provided files from a repository and stores scan results.
func ScanFiles(repo string, files []string) ([]models.ScanResults, error) {
	var (
		results []models.ScanResults
		mu      sync.Mutex                     // Protects concurrent writes to results.
		wg      sync.WaitGroup                 // WaitGroup to track file processing.
		sem     = make(chan struct{}, 3)       // Limits to 3 concurrent file processes.
		errChan = make(chan error, len(files)) // Collects errors from goroutines.
	)

	for _, file := range files {
		if !strings.HasSuffix(file, ".json") {
			log.Printf("INFO: Skipping non-JSON file: %s", file)
			continue
		}

		wg.Add(1)
		sem <- struct{}{} // Acquire a semaphore slot.

		go func(file string) {
			defer wg.Done()
			defer func() { <-sem }() // Release slot.

			content, err := github.FetchFile(repo, file)
			if err != nil {
				errChan <- err
				log.Printf("ERROR: FetchFile failed for %s: %v", file, err)
				return
			}

			scans := github.ParseJSON(content, file)
			if len(scans) == 0 {
				log.Printf("WARN: No scan results parsed from file: %s", file)
				return
			}

			for _, parsed := range scans {
				if err = database.StoreScanResults(parsed.ScanID, parsed.ScanTime, parsed.Status, parsed.ResourceType, parsed.ResourceName); err != nil {
					errChan <- err
					log.Printf("ERROR: Storing scan result for scanID %s: %v", parsed.ScanID, err)
					return
				}

				for _, vulnerability := range parsed.Vulnerabilities {
					if err = database.StoreVulnerability(parsed.ScanID, vulnerability.ID, vulnerability.Severity, vulnerability.CVSS, vulnerability.Status,
						vulnerability.PackageName, vulnerability.CurrentVersion, vulnerability.FixedVersion, vulnerability.Description, vulnerability.PublishedDate, vulnerability.Link); err != nil {
						errChan <- err
						log.Printf("ERROR: Storing vulnerability %s for scanID %s: %v", vulnerability.ID, parsed.ScanID, err)
						return
					}

					for _, rf := range vulnerability.RiskFactors {
						if err = database.StoreRiskFactor(parsed.ScanID, vulnerability.ID, rf); err != nil {
							errChan <- err
							log.Printf("ERROR: Storing risk factor for vulnerability %s in scanID %s: %v", vulnerability.ID, parsed.ScanID, err)
							return
						}
					}
				}

				if parsed.Summary != nil {
					critical := parsed.Summary.SeverityCounts["Critical"]
					high := parsed.Summary.SeverityCounts["High"]
					medium := parsed.Summary.SeverityCounts["Medium"]
					low := parsed.Summary.SeverityCounts["Low"]

					if err = database.StoreScanSummary(parsed.ScanID, parsed.Summary.TotalVulnerabilities, critical, high, medium, low, parsed.Summary.FixableCount, parsed.Summary.Compliant); err != nil {
						errChan <- err
						log.Printf("ERROR: Storing scan summary for scanID %s: %v", parsed.ScanID, err)
						return
					}
				}

				if parsed.Metadata != nil {
					if err = database.StoreScanMetadata(parsed.ScanID, parsed.Metadata.ScannerVersion, parsed.Metadata.PoliciesVersion); err != nil {
						errChan <- err
						log.Printf("ERROR: Storing scan metadata for scanID %s: %v", parsed.ScanID, err)
						return
					}

					for _, rule := range parsed.Metadata.ScanningRules {
						if err = database.StoreScanningRule(parsed.ScanID, rule); err != nil {
							errChan <- err
							log.Printf("ERROR: Storing scanning rule for scanID %s: %v", parsed.ScanID, err)
							return
						}
					}

					for _, path := range parsed.Metadata.ExcludedPaths {
						if err = database.StoreExcludedPath(parsed.ScanID, path); err != nil {
							errChan <- err
							log.Printf("ERROR: Storing excluded path for scanID %s: %v", parsed.ScanID, err)
							return
						}
					}
				}

				mu.Lock()
				results = append(results, parsed)
				mu.Unlock()
			}
		}(file)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			log.Printf("ERROR: ScanFiles encountered an error: %v", err)
			return nil, err
		}
	}

	log.Printf("INFO: Completed scanning files; total processed: %d", len(results))
	return results, nil
}
