// Code generated from traust-contracts v0.44.0. DO NOT EDIT.

package types

import (
	"github.com/traust-security/traust-sdk/go/v1/enums"
)

type Report struct {
	AsvsCoverage         []AsvsChapter         `json:"asvs_coverage,omitempty"`
	DependencyAudit      *DependencyAudit      `json:"dependency_audit,omitempty"`
	DispositionSummary   *DispositionSummary   `json:"disposition_summary,omitempty"`
	ExecutiveSummary     ExecutiveSummary      `json:"executive_summary"`
	Findings             []ReportFinding       `json:"findings"`
	FindingsSummary      []SeverityCountEntry  `json:"findings_summary"`
	Footer               *string               `json:"footer,omitempty"`
	Metadata             ReportMetadata        `json:"metadata"`
	NegativeResults      []NegativeResult      `json:"negative_results,omitempty"`
	PeachIsolationReview *PeachIsolationReview `json:"peach_isolation_review,omitempty"`
	RemediationRoadmap   []RoadmapItem         `json:"remediation_roadmap"`
	ScannerCorrelation   []ScannerEntry        `json:"scanner_correlation,omitempty"`
	SeverityCriteria     []SeverityCriterion   `json:"severity_criteria"`
	Title                string                `json:"title"`
}

type AsvsChapter struct {
	Area                 string          `json:"area"`
	Chapter              string          `json:"chapter"`
	HighestSeverity      *enums.Severity `json:"highest_severity,omitempty"`
	RequirementsAssessed *int            `json:"requirements_assessed,omitempty"`
	Violations           *int            `json:"violations,omitempty"`
}

type DependencyAudit struct {
	Entries []DependencyAuditEntriesItem `json:"entries,omitempty"`
	Prose   *string                      `json:"prose,omitempty"`
}

type DependencyAuditEntriesItem struct {
	Notes   *string `json:"notes,omitempty"`
	Package string  `json:"package"`
	Status  string  `json:"status"`
	Version string  `json:"version"`
}

type DispositionSummary struct {
	ByResolution      DispositionSummaryByResolution            `json:"by_resolution"`
	ByValidity        DispositionSummaryByValidity              `json:"by_validity"`
	Conflicts         []string                                  `json:"conflicts,omitempty"`
	GeneratedAt       string                                    `json:"generated_at"`
	LayerRef          string                                    `json:"layer_ref"`
	NeedsReviewCount  *int                                      `json:"needs_review_count,omitempty"`
	SeverityOverrides []DispositionSummarySeverityOverridesItem `json:"severity_overrides,omitempty"`
}

type DispositionSummaryByResolution struct {
	FixInProgress        int `json:"fix_in_progress"`
	Open                 int `json:"open"`
	PartiallyResolved    int `json:"partially_resolved"`
	RegressionIntroduced int `json:"regression_introduced"`
	Resolved             int `json:"resolved"`
	RiskAccepted         int `json:"risk_accepted"`
}

type DispositionSummaryByValidity struct {
	Confirmed     int  `json:"confirmed"`
	Corrected     int  `json:"corrected"`
	FalsePositive int  `json:"false_positive"`
	Hardening     *int `json:"hardening,omitempty"`
	NotVerified   int  `json:"not_verified"`
}

type DispositionSummarySeverityOverridesItem struct {
	At        string         `json:"at"`
	By        string         `json:"by"`
	Finding   string         `json:"finding"`
	From      interface{}    `json:"from,omitempty"`
	Rationale *string        `json:"rationale,omitempty"`
	Severity  enums.Severity `json:"severity"`
}

type EvidenceBlock struct {
	Caption  *string `json:"caption,omitempty"`
	Code     string  `json:"code"`
	Language *string `json:"language,omitempty"`
}

type ExecutiveSummary struct {
	KeyRisks             []string                       `json:"key_risks,omitempty"`
	PositiveObservations []string                       `json:"positive_observations,omitempty"`
	Prose                string                         `json:"prose"`
	SeverityCounts       ExecutiveSummarySeverityCounts `json:"severity_counts"`
}

type ExecutiveSummarySeverityCounts struct {
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Informational int `json:"informational"`
	Low           int `json:"low"`
	Medium        int `json:"medium"`
}

type Location struct {
	Description *string `json:"description,omitempty"`
	Lines       *string `json:"lines,omitempty"`
	Path        string  `json:"path"`
}

type NegativeResult struct {
	Area   string  `json:"area"`
	Files  *string `json:"files,omitempty"`
	Result string  `json:"result"`
}

type PeachIsolationReview struct {
	Applicable bool                                 `json:"applicable"`
	Interfaces []PeachIsolationReviewInterfacesItem `json:"interfaces,omitempty"`
	Rationale  *string                              `json:"rationale,omitempty"`
}

type PeachIsolationReviewInterfacesItem struct {
	BoundaryType  enums.PeachBoundaryType   `json:"boundary_type"`
	Complexity    enums.InterfaceComplexity `json:"complexity"`
	FindingIds    []string                  `json:"finding_ids,omitempty"`
	HardeningGaps []string                  `json:"hardening_gaps,omitempty"`
	Name          string                    `json:"name"`
	Notes         *string                   `json:"notes,omitempty"`
	Shared        bool                      `json:"shared"`
}

type ReportDisposition struct {
	Assurance              *enums.DispositionAssurance        `json:"assurance,omitempty"`
	Conflict               *bool                              `json:"conflict,omitempty"`
	Events                 []string                           `json:"events"`
	FpOverridden           *bool                              `json:"fp_overridden,omitempty"`
	FpReassertionBlocked   *bool                              `json:"fp_reassertion_blocked,omitempty"`
	LastUpdated            string                             `json:"last_updated"`
	RefutedAwaitingSignoff *bool                              `json:"refuted_awaiting_signoff,omitempty"`
	Resolution             enums.DispositionResolution        `json:"resolution"`
	SeverityOverride       *ReportDispositionSeverityOverride `json:"severity_override,omitempty"`
	Validity               enums.Validity                     `json:"validity"`
}

type ReportDispositionSeverityOverride struct {
	At        string         `json:"at"`
	By        string         `json:"by"`
	Rationale *string        `json:"rationale,omitempty"`
	Severity  enums.Severity `json:"severity"`
}

type ReportFinding struct {
	AsvsReferences      []string                   `json:"asvs_references,omitempty"`
	AttackPattern       *string                    `json:"attack_pattern,omitempty"`
	Capec               []string                   `json:"capec,omitempty"`
	Category            *string                    `json:"category,omitempty"`
	Cvss                *ReportFindingCvss         `json:"cvss,omitempty"`
	Cwes                []string                   `json:"cwes"`
	Dependency          *ReportFindingDependency   `json:"dependency,omitempty"`
	Description         string                     `json:"description"`
	Disposition         *ReportDisposition         `json:"disposition,omitempty"`
	EffectiveSeverity   *enums.Severity            `json:"effective_severity,omitempty"`
	Evidence            []EvidenceBlock            `json:"evidence,omitempty"`
	Fingerprint         *string                    `json:"fingerprint,omitempty"`
	FingerprintAlgo     *string                    `json:"fingerprint_algo,omitempty"`
	Id                  string                     `json:"id"`
	IsolationBoundary   *string                    `json:"isolation_boundary,omitempty"`
	IsolationDimensions []enums.IsolationDimension `json:"isolation_dimensions,omitempty"`
	Locations           []Location                 `json:"locations"`
	Origin              *enums.FindingOrigin       `json:"origin,omitempty"`
	Passes              []int                      `json:"passes,omitempty"`
	PeachReferences     []string                   `json:"peach_references,omitempty"`
	PqcClassification   *enums.PqcClassification   `json:"pqc_classification,omitempty"`
	Remediation         string                     `json:"remediation"`
	RemediationEffort   *enums.RemediationEffort   `json:"remediation_effort,omitempty"`
	Severity            enums.Severity             `json:"severity"`
	SourceFindings      []string                   `json:"source_findings,omitempty"`
	Title               string                     `json:"title"`
	ValidationStatus    *enums.Validity            `json:"validation_status,omitempty"`
}

type ReportFindingCvss struct {
	Score  float64 `json:"score"`
	Vector string  `json:"vector"`
}

type ReportFindingDependency struct {
	Advisory         string                         `json:"advisory"`
	Classification   *enums.ImpactClassification    `json:"classification,omitempty"`
	Ecosystem        *enums.Ecosystem               `json:"ecosystem,omitempty"`
	EvidenceLevel    *enums.DependencyEvidenceLevel `json:"evidence_level,omitempty"`
	FixedVersion     *string                        `json:"fixed_version,omitempty"`
	ImpactArtifact   *string                        `json:"impact_artifact,omitempty"`
	InstalledVersion *string                        `json:"installed_version,omitempty"`
	Module           string                         `json:"module"`
	Purl             *string                        `json:"purl,omitempty"`
	VulnerableRange  *string                        `json:"vulnerable_range,omitempty"`
}

type ReportMetadata struct {
	Additional   *ReportMetadataAdditional   `json:"additional,omitempty"`
	AuditProfile *enums.AuditProfile         `json:"audit_profile,omitempty"`
	Auditor      *string                     `json:"auditor,omitempty"`
	Commit       *string                     `json:"commit,omitempty"`
	Date         string                      `json:"date"`
	Framework    *string                     `json:"framework,omitempty"`
	LocBreakdown *ReportMetadataLocBreakdown `json:"loc_breakdown,omitempty"`
	LocReviewed  interface{}                 `json:"loc_reviewed,omitempty"`
	Methodology  *string                     `json:"methodology,omitempty"`
	Ref          *string                     `json:"ref,omitempty"`
	RefKind      *enums.RefKind              `json:"ref_kind,omitempty"`
	Repository   *string                     `json:"repository,omitempty"`
	Scope        string                      `json:"scope"`
	Tools        []string                    `json:"tools,omitempty"`
}

type ReportMetadataAdditional struct {
	ContractsVersion *string `json:"contracts_version,omitempty"`
	HarnessVersion   *string `json:"harness_version,omitempty"`
}

type ReportMetadataLocBreakdown struct {
	ByLanguage map[string]int `json:"by_language,omitempty"`
	Excludes   []string       `json:"excludes,omitempty"`
	Tool       *string        `json:"tool,omitempty"`
	Total      int            `json:"total"`
}

type RoadmapItem struct {
	Action    string   `json:"action"`
	Addresses []string `json:"addresses"`
	Effort    *string  `json:"effort,omitempty"`
	Priority  string   `json:"priority"`
}

type ScannerEntry struct {
	Configured *bool    `json:"configured,omitempty"`
	FindingIds []string `json:"finding_ids,omitempty"`
	Location   *string  `json:"location,omitempty"`
	Notes      *string  `json:"notes,omitempty"`
	Result     string   `json:"result"`
	RuleId     *string  `json:"rule_id,omitempty"`
	Tool       string   `json:"tool"`
}

type SeverityCountEntry struct {
	Count      int            `json:"count"`
	FindingIds []string       `json:"finding_ids"`
	Severity   enums.Severity `json:"severity"`
}

type SeverityCriterion struct {
	CvssRange  interface{}    `json:"cvss_range,omitempty"`
	Definition string         `json:"definition"`
	Level      enums.Severity `json:"level"`
}
