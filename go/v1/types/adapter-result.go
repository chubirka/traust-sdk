// Code generated from traust-contracts v0.46.0. DO NOT EDIT.

package types

type AdapterResult struct {
	Findings   []ReportFinding `json:"findings"`
	FocusAreas []string        `json:"focus_areas,omitempty"`
	Metadata   Metadata        `json:"metadata"`
	ScannedAt  string          `json:"scanned_at"`
	Summary    *Summary        `json:"summary,omitempty"`
	Target     string          `json:"target"`
}

type Metadata struct {
	ScannerVersion *string `json:"scanner_version,omitempty"`
	Tool           string  `json:"tool"`
}

type Summary struct {
	BySeverity map[string]int `json:"by_severity,omitempty"`
	Total      int            `json:"total"`
}
