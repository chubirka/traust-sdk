// Code generated from traust-contracts v0.44.0. DO NOT EDIT.

package types

import (
	"github.com/traust-security/traust-sdk/go/v1/enums"
)

type CloudConfigAudit struct {
	Findings []CloudConfigAuditFindingsItem `json:"findings"`
	Gaps     []string                       `json:"gaps,omitempty"`
	Metadata CloudConfigAuditMetadata       `json:"metadata"`
	Summary  CloudConfigAuditSummary        `json:"summary"`
	Title    string                         `json:"title"`
}

type CloudConfigAuditFindingsItem struct {
	CheckId             string                                      `json:"check_id"`
	ControlRefs         []string                                    `json:"control_refs,omitempty"`
	Cwe                 interface{}                                 `json:"cwe,omitempty"`
	ExternalCorrelation []string                                    `json:"external_correlation,omitempty"`
	FactIds             []string                                    `json:"fact_ids"`
	Fingerprint         *string                                     `json:"fingerprint,omitempty"`
	FingerprintAlgo     *string                                     `json:"fingerprint_algo,omitempty"`
	Framework           string                                      `json:"framework"`
	Id                  string                                      `json:"id"`
	IsolationBoundary   *string                                     `json:"isolation_boundary,omitempty"`
	IsolationDimensions []enums.IsolationDimension                  `json:"isolation_dimensions,omitempty"`
	Locations           []CloudConfigAuditFindingsItemLocationsItem `json:"locations,omitempty"`
	Provider            enums.CloudProvider                         `json:"provider"`
	Rationale           *string                                     `json:"rationale,omitempty"`
	Remediation         interface{}                                 `json:"remediation,omitempty"`
	ScannerSeverity     *enums.ScannerSeverity                      `json:"scanner_severity,omitempty"`
	Severity            enums.Severity                              `json:"severity"`
	Status              enums.CloudConfigFindingStatus              `json:"status"`
	Title               string                                      `json:"title"`
}

type CloudConfigAuditFindingsItemLocationsItem struct {
	FileLineRange interface{} `json:"file_line_range,omitempty"`
	FilePath      *string     `json:"file_path,omitempty"`
	Resource      interface{} `json:"resource,omitempty"`
}

type CloudConfigAuditMetadata struct {
	AssessmentMode     interface{}                                      `json:"assessment_mode"`
	CheckovVersion     string                                           `json:"checkov_version"`
	DeterministicSteps []CloudConfigAuditMetadataDeterministicStepsItem `json:"deterministic_steps"`
	FactsRef           string                                           `json:"facts_ref"`
	FactsSnapshotId    string                                           `json:"facts_snapshot_id"`
	Frameworks         []string                                         `json:"frameworks,omitempty"`
	GeneratedAt        *string                                          `json:"generated_at,omitempty"`
	HarnessVersion     string                                           `json:"harness_version"`
	Ref                *string                                          `json:"ref,omitempty"`
	RefKind            *enums.RefKind                                   `json:"ref_kind,omitempty"`
	Repository         interface{}                                      `json:"repository,omitempty"`
	Target             string                                           `json:"target"`
	TargetHead         interface{}                                      `json:"target_head,omitempty"`
}

type CloudConfigAuditMetadataDeterministicStepsItem struct {
	Invocation string  `json:"invocation"`
	Tool       string  `json:"tool"`
	Version    *string `json:"version,omitempty"`
}

type CloudConfigAuditSummary struct {
	ByProvider  map[string]int `json:"by_provider,omitempty"`
	BySeverity  map[string]int `json:"by_severity,omitempty"`
	Confirmed   int            `json:"confirmed"`
	FactsTotal  int            `json:"facts_total"`
	Gaps        int            `json:"gaps"`
	NeedsReview int            `json:"needs_review"`
	Suppressed  int            `json:"suppressed"`
}
