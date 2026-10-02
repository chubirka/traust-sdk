// Code generated from traust-contracts v0.48.1. DO NOT EDIT.

package types

import (
	"github.com/traust-security/traust-sdk/go/v1/enums"
)

type CloudConfigFindingsCurrent struct {
	DispositionSummary CloudConfigFindingsCurrentDispositionSummary `json:"disposition_summary"`
	Findings           []CloudConfigFindingsCurrentFindingsItem     `json:"findings"`
	Gaps               []string                                     `json:"gaps,omitempty"`
	Metadata           CloudConfigFindingsCurrentMetadata           `json:"metadata"`
	Summary            CloudConfigFindingsCurrentSummary            `json:"summary"`
	Title              string                                       `json:"title"`
}

type CloudConfigFindingsCurrentDispositionSummary struct {
	ByResolution      map[string]int                                                      `json:"by_resolution"`
	ByValidity        map[string]int                                                      `json:"by_validity"`
	Conflicts         []string                                                            `json:"conflicts"`
	GeneratedAt       string                                                              `json:"generated_at"`
	LayerRef          string                                                              `json:"layer_ref"`
	NeedsReviewCount  int                                                                 `json:"needs_review_count"`
	SeverityOverrides []CloudConfigFindingsCurrentDispositionSummarySeverityOverridesItem `json:"severity_overrides"`
}

type CloudConfigFindingsCurrentDispositionSummarySeverityOverridesItem struct {
	At        string         `json:"at"`
	By        string         `json:"by"`
	Finding   string         `json:"finding"`
	From      interface{}    `json:"from,omitempty"`
	Rationale *string        `json:"rationale,omitempty"`
	Severity  enums.Severity `json:"severity"`
}

type CloudConfigFindingsCurrentFindingsItem struct {
	CheckId             string                                                `json:"check_id"`
	ControlRefs         []string                                              `json:"control_refs,omitempty"`
	Cwe                 interface{}                                           `json:"cwe,omitempty"`
	Disposition         CloudConfigFindingsCurrentFindingsItemDisposition     `json:"disposition"`
	EffectiveSeverity   enums.Severity                                        `json:"effective_severity"`
	ExternalCorrelation []string                                              `json:"external_correlation,omitempty"`
	FactIds             []string                                              `json:"fact_ids"`
	Fingerprint         *string                                               `json:"fingerprint,omitempty"`
	FingerprintAlgo     *string                                               `json:"fingerprint_algo,omitempty"`
	Framework           string                                                `json:"framework"`
	Id                  string                                                `json:"id"`
	IsolationBoundary   *string                                               `json:"isolation_boundary,omitempty"`
	IsolationDimensions []enums.IsolationDimension                            `json:"isolation_dimensions,omitempty"`
	Locations           []CloudConfigFindingsCurrentFindingsItemLocationsItem `json:"locations,omitempty"`
	Provider            enums.CloudProvider                                   `json:"provider"`
	Rationale           *string                                               `json:"rationale,omitempty"`
	Remediation         interface{}                                           `json:"remediation,omitempty"`
	ScannerSeverity     *enums.ScannerSeverity                                `json:"scanner_severity,omitempty"`
	Severity            enums.Severity                                        `json:"severity"`
	Status              enums.CloudConfigFindingStatus                        `json:"status"`
	Title               string                                                `json:"title"`
	ValidationStatus    enums.Validity                                        `json:"validation_status"`
}

type CloudConfigFindingsCurrentFindingsItemDisposition struct {
	Assurance              enums.DispositionAssurance                                         `json:"assurance"`
	Conflict               interface{}                                                        `json:"conflict,omitempty"`
	Events                 []string                                                           `json:"events"`
	FpOverridden           interface{}                                                        `json:"fp_overridden,omitempty"`
	FpReassertionBlocked   interface{}                                                        `json:"fp_reassertion_blocked,omitempty"`
	LastUpdated            string                                                             `json:"last_updated"`
	RefutedAwaitingSignoff interface{}                                                        `json:"refuted_awaiting_signoff,omitempty"`
	Resolution             enums.DispositionResolution                                        `json:"resolution"`
	SeverityOverride       *CloudConfigFindingsCurrentFindingsItemDispositionSeverityOverride `json:"severity_override,omitempty"`
	Validity               enums.Validity                                                     `json:"validity"`
}

type CloudConfigFindingsCurrentFindingsItemDispositionSeverityOverride struct {
	At        string         `json:"at"`
	By        string         `json:"by"`
	Rationale *string        `json:"rationale,omitempty"`
	Severity  enums.Severity `json:"severity"`
}

type CloudConfigFindingsCurrentFindingsItemLocationsItem struct {
	FileLineRange interface{} `json:"file_line_range,omitempty"`
	FilePath      *string     `json:"file_path,omitempty"`
	Resource      interface{} `json:"resource,omitempty"`
}

type CloudConfigFindingsCurrentMetadata struct {
	Additional         CloudConfigFindingsCurrentMetadataAdditional               `json:"additional"`
	AssessmentMode     interface{}                                                `json:"assessment_mode"`
	CheckovVersion     string                                                     `json:"checkov_version"`
	Date               string                                                     `json:"date"`
	DeterministicSteps []CloudConfigFindingsCurrentMetadataDeterministicStepsItem `json:"deterministic_steps"`
	FactsRef           string                                                     `json:"facts_ref"`
	FactsSnapshotId    string                                                     `json:"facts_snapshot_id"`
	Frameworks         []string                                                   `json:"frameworks,omitempty"`
	GeneratedAt        *string                                                    `json:"generated_at,omitempty"`
	HarnessVersion     string                                                     `json:"harness_version"`
	Ref                *string                                                    `json:"ref,omitempty"`
	RefKind            *enums.RefKind                                             `json:"ref_kind,omitempty"`
	Repository         interface{}                                                `json:"repository,omitempty"`
	Target             string                                                     `json:"target"`
	TargetHead         interface{}                                                `json:"target_head,omitempty"`
}

type CloudConfigFindingsCurrentMetadataAdditional struct {
	Cumulative CloudConfigFindingsCurrentMetadataAdditionalCumulative `json:"cumulative"`
}

type CloudConfigFindingsCurrentMetadataAdditionalCumulative struct {
	GeneratedAt        string      `json:"generated_at"`
	Layer              string      `json:"layer"`
	OriginalReportDate interface{} `json:"original_report_date,omitempty"`
	SourceAudit        string      `json:"source_audit"`
}

type CloudConfigFindingsCurrentMetadataDeterministicStepsItem struct {
	Invocation string  `json:"invocation"`
	Tool       string  `json:"tool"`
	Version    *string `json:"version,omitempty"`
}

type CloudConfigFindingsCurrentSummary struct {
	ByProvider  map[string]int `json:"by_provider,omitempty"`
	BySeverity  map[string]int `json:"by_severity,omitempty"`
	Confirmed   int            `json:"confirmed"`
	FactsTotal  int            `json:"facts_total"`
	Gaps        int            `json:"gaps"`
	NeedsReview int            `json:"needs_review"`
	Suppressed  int            `json:"suppressed"`
}
