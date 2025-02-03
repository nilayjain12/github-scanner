package models

type ScanResultsWrapper struct {
    ScanResults ScanResults `json:"scanResults"`
}

// ScanRequestPayload is the payload sent to the /scan endpoint.
type ScanRequestPayload struct {
	Repo  string   `json:"repo"`
	Files []string `json:"files"`
}

type QueryRequestPayload struct {
	Filters struct {
		Severity string `json:"severity"`
	} `json:"filters"`
}

// Vulnerability represents a vulnerability record.
type Vulnerability struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity"`
	CVSS           float64  `json:"cvss"`
	Status         string   `json:"status"`
	PackageName    string   `json:"package_name"`
	CurrentVersion string   `json:"current_version"`
	FixedVersion   string   `json:"fixed_version"`
	Description    string   `json:"description"`
	PublishedDate  string   `json:"published_date"`
	Link           string   `json:"link"`
	RiskFactors    []string `json:"risk_factors"`
}

// ScanMetadata holds additional metadata about the scan.
type ScanMetadata struct {
	ScannerVersion  string   `json:"scanner_version"`
	PoliciesVersion string   `json:"policies_version"`
	ScanningRules   []string `json:"scanning_rules"`
	ExcludedPaths   []string `json:"excluded_paths"`
}

// ScanSummary holds a summary of the scan results.
type ScanSummary struct {
	TotalVulnerabilities int            `json:"total_vulnerabilities"`
	SeverityCounts       map[string]int `json:"severity_counts"` // Expected keys: "Critical", "High", "Medium", "Low"
	FixableCount         int            `json:"fixable_count"`
	Compliant            bool           `json:"compliant"`
}

// ScanResults represents the full scan result from a JSON file.
type ScanResults struct {
	ScanID          string          `json:"scan_id"`
	ScanTime        string          `json:"timestamp"`
	Status          string          `json:"scan_status"`
	ResourceType    string          `json:"resource_type"`
	ResourceName    string          `json:"resource_name"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	// "summary" in the JSON corresponds to the scan summary.
	Summary  *ScanSummary `json:"summary"`
	// "metadata" in the JSON corresponds to scan metadata.
	Metadata *ScanMetadata `json:"scan_metadata"`
	// SourceFile is used internally to record which file this scan came from.
	SourceFile string `json:"source_file"`
}
