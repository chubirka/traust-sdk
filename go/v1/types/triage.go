// Code generated from traust-contracts v0.47.0. DO NOT EDIT.

package types

import (
	"github.com/traust-security/traust-sdk/go/v1/enums"
)

type Triage struct {
	Findings        []TriageFinding `json:"findings"`
	Summary         TriageSummary   `json:"summary"`
	TriageCompleted string          `json:"triage_completed"`
	TriageContext   TriageContext   `json:"triage_context"`
}

type TriageContext struct {
	Environment     string      `json:"environment"`
	FindingsPath    *string     `json:"findings_path,omitempty"`
	HarnessVersion  string      `json:"harness_version"`
	Mode            *string     `json:"mode,omitempty"`
	NoiseTolerance  *string     `json:"noise_tolerance,omitempty"`
	ReemitMethod    *string     `json:"reemit_method,omitempty"`
	Reemitted       *string     `json:"reemitted,omitempty"`
	Repo            string      `json:"repo"`
	RerunOf         *string     `json:"rerun_of,omitempty"`
	Scoring         *string     `json:"scoring,omitempty"`
	SourceReport    *string     `json:"source_report,omitempty"`
	ThreatModel     interface{} `json:"threat_model,omitempty"`
	VotesPerFinding int         `json:"votes_per_finding"`
}

type TriageFinding struct {
	Absorbed          []string      `json:"absorbed,omitempty"`
	AccessLevel       interface{}   `json:"access_level,omitempty"`
	Category          interface{}   `json:"category,omitempty"`
	ClaimedSeverity   interface{}   `json:"claimed_severity,omitempty"`
	Component         interface{}   `json:"component,omitempty"`
	Confidence        interface{}   `json:"confidence,omitempty"`
	DuplicateOf       interface{}   `json:"duplicate_of,omitempty"`
	ExclusionRule     interface{}   `json:"exclusion_rule,omitempty"`
	File              interface{}   `json:"file,omitempty"`
	Fingerprint       *string       `json:"fingerprint,omitempty"`
	FingerprintAlgo   *string       `json:"fingerprint_algo,omitempty"`
	FirstLinks        []string      `json:"first_links,omitempty"`
	Id                string        `json:"id"`
	Line              interface{}   `json:"line,omitempty"`
	MissingFields     []string      `json:"missing_fields,omitempty"`
	OrigId            interface{}   `json:"orig_id,omitempty"`
	OwnerHint         interface{}   `json:"owner_hint,omitempty"`
	Preconditions     []string      `json:"preconditions,omitempty"`
	Rationale         interface{}   `json:"rationale,omitempty"`
	Recommendation    interface{}   `json:"recommendation,omitempty"`
	RefuteReasons     []string      `json:"refute_reasons,omitempty"`
	Severity          interface{}   `json:"severity,omitempty"`
	SeverityAlignment interface{}   `json:"severity_alignment,omitempty"`
	SeverityLabel     interface{}   `json:"severity_label,omitempty"`
	Source            interface{}   `json:"source,omitempty"`
	ThreatMatch       interface{}   `json:"threat_match,omitempty"`
	Title             string        `json:"title"`
	Verdict           enums.Verdict `json:"verdict"`
	VerifyVerdict     *string       `json:"verify_verdict,omitempty"`
	VoteBreakdown     interface{}   `json:"vote_breakdown,omitempty"`
}

type TriageSummary struct {
	BySeverity      TriageSummaryBySeverity `json:"by_severity"`
	Duplicates      int                     `json:"duplicates"`
	FalsePositives  int                     `json:"false_positives"`
	Hardening       int                     `json:"hardening"`
	InputCount      int                     `json:"input_count"`
	NeedsManualTest *int                    `json:"needs_manual_test,omitempty"`
	TruePositives   int                     `json:"true_positives"`
	Undetermined    int                     `json:"undetermined"`
}

type TriageSummaryBySeverity struct {
	Critical      int  `json:"critical"`
	High          int  `json:"high"`
	Informational *int `json:"informational,omitempty"`
	Low           int  `json:"low"`
	Medium        int  `json:"medium"`
}

type VoteBreakdown struct {
	CannotVerify  int `json:"cannot_verify"`
	FalsePositive int `json:"false_positive"`
	Hardening     int `json:"hardening"`
	TruePositive  int `json:"true_positive"`
}
