// Code generated from traust-contracts v0.47.0. DO NOT EDIT.

package types

import (
	"github.com/traust-security/traust-sdk/go/v1/enums"
)

type Validation struct {
	AttackChains       []AttackChain      `json:"attack_chains"`
	ExecutionLogRef    string             `json:"execution_log_ref"`
	ExecutionLogSha256 *string            `json:"execution_log_sha256,omitempty"`
	Footer             *string            `json:"footer,omitempty"`
	Metadata           ValidationMetadata `json:"metadata"`
	NegativeResults    []NegativeResult   `json:"negative_results,omitempty"`
	NovelFindings      []NovelFinding     `json:"novel_findings"`
	SourceReports      []SourceReport     `json:"source_reports"`
	Summary            ValidationSummary  `json:"summary"`
	Title              string             `json:"title"`
	ValidatedFindings  []ValidatedFinding `json:"validated_findings"`
}

type AttackChain struct {
	ChainId         string                  `json:"chain_id"`
	EntryPoint      string                  `json:"entry_point"`
	MitreAttackRefs []string                `json:"mitre_attack_refs,omitempty"`
	Name            string                  `json:"name"`
	Narrative       *string                 `json:"narrative,omitempty"`
	Steps           []StepResult            `json:"steps"`
	TerminalAsset   string                  `json:"terminal_asset"`
	Verdict         enums.ValidationVerdict `json:"verdict"`
}

type DifferentialProbe struct {
	ClaimedObserved  interface{} `json:"claimed_observed,omitempty"`
	Discriminated    bool        `json:"discriminated"`
	NeighborAction   string      `json:"neighbor_action"`
	NeighborExpected interface{} `json:"neighbor_expected,omitempty"`
	NeighborObserved interface{} `json:"neighbor_observed,omitempty"`
}

type EvidenceArtifact struct {
	Caption  *string                      `json:"caption,omitempty"`
	Path     string                       `json:"path"`
	Redacted *bool                        `json:"redacted,omitempty"`
	Sha256   *string                      `json:"sha256,omitempty"`
	Type     enums.ValidationEvidenceType `json:"type"`
}

type Fingerprint struct {
	Adapter  enums.ValidationAdapter `json:"adapter"`
	Details  map[string]interface{}  `json:"details,omitempty"`
	Digest   *string                 `json:"digest,omitempty"`
	Identity string                  `json:"identity"`
	Version  *string                 `json:"version,omitempty"`
}

type NovelFinding struct {
	ChainContext    interface{}            `json:"chain_context,omitempty"`
	DiscoveryMethod *enums.DiscoveryMethod `json:"discovery_method,omitempty"`
	StepRef         *string                `json:"step_ref,omitempty"`
}

type PositiveControl struct {
	Kind     enums.PositiveControlKind `json:"kind"`
	Name     string                    `json:"name"`
	Observed interface{}               `json:"observed,omitempty"`
	Ok       bool                      `json:"ok"`
	Target   interface{}               `json:"target,omitempty"`
	Verb     interface{}               `json:"verb,omitempty"`
}

type ReplayArtifact struct {
	ClusterFingerprintSha interface{} `json:"cluster_fingerprint_sha,omitempty"`
	InputsRef             interface{} `json:"inputs_ref,omitempty"`
	ScriptRef             string      `json:"script_ref"`
}

type SeverityValidation struct {
	ClaimedScore              interface{}                    `json:"claimed_score,omitempty"`
	ClaimedVector             interface{}                    `json:"claimed_vector,omitempty"`
	Delta                     interface{}                    `json:"delta,omitempty"`
	Demonstrated              SeverityValidationDemonstrated `json:"demonstrated"`
	DemonstratedScoreEstimate interface{}                    `json:"demonstrated_score_estimate,omitempty"`
	Proposal                  interface{}                    `json:"proposal,omitempty"`
}

type SeverityValidationDemonstrated struct {
	AttackVector       *string     `json:"attack_vector,omitempty"`
	Impacts            interface{} `json:"impacts,omitempty"`
	PrivilegesRequired *string     `json:"privileges_required,omitempty"`
	ScopeCrossed       interface{} `json:"scope_crossed,omitempty"`
	UserInteraction    *string     `json:"user_interaction,omitempty"`
}

type SourceReport struct {
	Kind   enums.ValidationSourceReportKind `json:"kind"`
	Path   string                           `json:"path"`
	Sha256 *string                          `json:"sha256,omitempty"`
}

type StepResult struct {
	Adapter           enums.ValidationAdapter             `json:"adapter"`
	Classification    enums.ValidationProbeClassification `json:"classification"`
	Controls          interface{}                         `json:"controls,omitempty"`
	Differential      interface{}                         `json:"differential,omitempty"`
	DurationMs        *int                                `json:"duration_ms,omitempty"`
	Error             *string                             `json:"error,omitempty"`
	Evidence          []EvidenceArtifact                  `json:"evidence,omitempty"`
	Expected          *string                             `json:"expected,omitempty"`
	FindingRef        interface{}                         `json:"finding_ref,omitempty"`
	NovelRef          interface{}                         `json:"novel_ref,omitempty"`
	Observed          *string                             `json:"observed,omitempty"`
	Replay            interface{}                         `json:"replay,omitempty"`
	RollbackOutput    *string                             `json:"rollback_output,omitempty"`
	RollbackPerformed interface{}                         `json:"rollback_performed,omitempty"`
	ScopeReason       *string                             `json:"scope_reason,omitempty"`
	SoundnessFlag     *string                             `json:"soundness_flag,omitempty"`
	StepId            string                              `json:"step_id"`
	Target            map[string]interface{}              `json:"target,omitempty"`
	Verb              string                              `json:"verb"`
	Verdict           enums.ValidationVerdict             `json:"verdict"`
}

type ValidatedFinding struct {
	ChainContext       interface{}               `json:"chain_context,omitempty"`
	ClaimedSeverity    *enums.Severity           `json:"claimed_severity,omitempty"`
	DeviationFromClaim *string                   `json:"deviation_from_claim,omitempty"`
	Evidence           []EvidenceArtifact        `json:"evidence,omitempty"`
	EvidenceGrade      *string                   `json:"evidence_grade,omitempty"`
	GradeRationale     interface{}               `json:"grade_rationale,omitempty"`
	NotAttemptedReason *string                   `json:"not_attempted_reason,omitempty"`
	ObservedImpact     *string                   `json:"observed_impact,omitempty"`
	RollbackPerformed  interface{}               `json:"rollback_performed,omitempty"`
	SeverityValidation interface{}               `json:"severity_validation,omitempty"`
	SoundnessFlag      *string                   `json:"soundness_flag,omitempty"`
	SourceId           string                    `json:"source_id"`
	SourceReport       string                    `json:"source_report"`
	Steps              []StepResult              `json:"steps,omitempty"`
	Technique          enums.ValidationTechnique `json:"technique"`
	Title              *string                   `json:"title,omitempty"`
	Verdict            enums.ValidationVerdict   `json:"verdict"`
}

type ValidationMetadata struct {
	Additional        map[string]interface{}      `json:"additional,omitempty"`
	Approval          *ValidationMetadataApproval `json:"approval,omitempty"`
	AuthorizedBy      *string                     `json:"authorized_by,omitempty"`
	Date              string                      `json:"date"`
	Engagement        *string                     `json:"engagement,omitempty"`
	Expires           *string                     `json:"expires,omitempty"`
	Flags             []string                    `json:"flags,omitempty"`
	HarnessVersion    string                      `json:"harness_version"`
	ScopeBindingMode  enums.ScopeBindingMode      `json:"scope_binding_mode"`
	ScopeSource       *string                     `json:"scope_source,omitempty"`
	TargetAttestation interface{}                 `json:"target_attestation,omitempty"`
	TargetEnvironment *string                     `json:"target_environment,omitempty"`
	TargetFingerprint []Fingerprint               `json:"target_fingerprint"`
}

type ValidationMetadataApproval struct {
	At          *string                       `json:"at,omitempty"`
	By          *string                       `json:"by,omitempty"`
	Environment *string                       `json:"environment,omitempty"`
	Mode        *enums.ValidationApprovalMode `json:"mode,omitempty"`
}

type ValidationSummary struct {
	ByTechnique        map[string]int             `json:"by_technique"`
	ByVerdict          ValidationSummaryByVerdict `json:"by_verdict"`
	ChainCount         *int                       `json:"chain_count,omitempty"`
	HighestImpactChain interface{}                `json:"highest_impact_chain,omitempty"`
	NovelCount         *int                       `json:"novel_count,omitempty"`
	Prose              *string                    `json:"prose,omitempty"`
}

type ValidationSummaryByVerdict struct {
	BlockedByScope int `json:"blocked_by_scope"`
	Confirmed      int `json:"confirmed"`
	Inconclusive   int `json:"inconclusive"`
	NotAttempted   int `json:"not_attempted"`
	Refuted        int `json:"refuted"`
}
