// Code generated from traust-contracts v0.44.0. DO NOT EDIT.

package types

import (
	"github.com/traust-security/traust-sdk/go/v1/enums"
)

type Verification struct {
	CommitTimeline   []TimelineEntry      `json:"commit_timeline"`
	Evidence         []PatchEvidence      `json:"evidence,omitempty"`
	Footer           *string              `json:"footer,omitempty"`
	Metadata         VerificationMetadata `json:"metadata"`
	Notes            *string              `json:"notes,omitempty"`
	Recommendations  []string             `json:"recommendations,omitempty"`
	Regressions      []Regression         `json:"regressions"`
	Summary          VerificationSummary  `json:"summary"`
	Title            string               `json:"title"`
	VerifiedFindings []VerifiedFinding    `json:"verified_findings"`
}

type CrossRepo struct {
	FixRef              interface{}                `json:"fix_ref,omitempty"`
	FixRepo             string                     `json:"fix_repo"`
	Propagation         enums.CrossRepoPropagation `json:"propagation"`
	PropagationEvidence interface{}                `json:"propagation_evidence,omitempty"`
}

type Regression struct {
	AttackPattern   *string         `json:"attack_pattern,omitempty"`
	Category        *string         `json:"category,omitempty"`
	Cvss            *RegressionCvss `json:"cvss,omitempty"`
	Cwes            []string        `json:"cwes"`
	Description     string          `json:"description"`
	Evidence        []EvidenceBlock `json:"evidence,omitempty"`
	Fingerprint     *string         `json:"fingerprint,omitempty"`
	FingerprintAlgo *string         `json:"fingerprint_algo,omitempty"`
	Id              string          `json:"id"`
	IntroducedBy    string          `json:"introduced_by"`
	Locations       []Location      `json:"locations"`
	Remediation     string          `json:"remediation"`
	RoutedId        *string         `json:"routed_id,omitempty"`
	Severity        enums.Severity  `json:"severity"`
	Title           string          `json:"title"`
}

type RegressionCvss struct {
	Score  float64 `json:"score"`
	Vector string  `json:"vector"`
}

type RemediationCommit struct {
	Author    string                           `json:"author"`
	Date      string                           `json:"date"`
	PrNumber  interface{}                      `json:"pr_number,omitempty"`
	Relevance enums.RemediationCommitRelevance `json:"relevance"`
	Sha       string                           `json:"sha"`
	ShortSha  string                           `json:"short_sha"`
	Subject   string                           `json:"subject"`
}

type TimelineEntry struct {
	Addresses []string    `json:"addresses"`
	Author    string      `json:"author"`
	Date      string      `json:"date"`
	FullSha   string      `json:"full_sha"`
	PrNumber  interface{} `json:"pr_number,omitempty"`
	Sha       string      `json:"sha"`
	Subject   string      `json:"subject"`
}

type VerificationMetadata struct {
	Additional     map[string]interface{} `json:"additional,omitempty"`
	Auditor        *string                `json:"auditor,omitempty"`
	Date           string                 `json:"date"`
	FixRef         interface{}            `json:"fix_ref,omitempty"`
	FixRepository  interface{}            `json:"fix_repository,omitempty"`
	Framework      *string                `json:"framework,omitempty"`
	HarnessVersion string                 `json:"harness_version"`
	OriginalCommit string                 `json:"original_commit"`
	OriginalReport string                 `json:"original_report"`
	PatchedCommit  string                 `json:"patched_commit"`
	PatchedRef     *string                `json:"patched_ref,omitempty"`
	Ref            *string                `json:"ref,omitempty"`
	RefKind        *enums.RefKind         `json:"ref_kind,omitempty"`
	Repository     string                 `json:"repository"`
	Scope          *string                `json:"scope,omitempty"`
}

type VerificationSummary struct {
	ByVerdict     VerificationSummaryByVerdict `json:"by_verdict"`
	Prose         *string                      `json:"prose,omitempty"`
	Regressions   int                          `json:"regressions"`
	TotalFindings int                          `json:"total_findings"`
}

type VerificationSummaryByVerdict struct {
	FalsePositive     int `json:"false_positive"`
	NewApproach       int `json:"new_approach"`
	PartiallyResolved int `json:"partially_resolved"`
	Regression        int `json:"regression"`
	Resolved          int `json:"resolved"`
	RiskAccepted      int `json:"risk_accepted"`
	Unresolved        int `json:"unresolved"`
}

type VerifiedFinding struct {
	CrossRepo            *CrossRepo                `json:"cross_repo,omitempty"`
	DispositionRationale interface{}               `json:"disposition_rationale,omitempty"`
	Evidence             VerifiedFindingEvidence   `json:"evidence"`
	OriginalId           string                    `json:"original_id"`
	OriginalSeverity     enums.Severity            `json:"original_severity"`
	OriginalTitle        string                    `json:"original_title"`
	RemediationCommits   []RemediationCommit       `json:"remediation_commits"`
	ResidualRisk         interface{}               `json:"residual_risk,omitempty"`
	ResidualSeverity     interface{}               `json:"residual_severity,omitempty"`
	Unattributed         bool                      `json:"unattributed"`
	Verdict              enums.VerificationVerdict `json:"verdict"`
}

type VerifiedFindingEvidence struct {
	Explanation        string  `json:"explanation"`
	FrameworkReference string  `json:"framework_reference"`
	OriginalCode       *string `json:"original_code,omitempty"`
	PatchedCode        *string `json:"patched_code,omitempty"`
}
