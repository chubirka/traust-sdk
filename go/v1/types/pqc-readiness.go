// Code generated from traust-contracts v0.47.0. DO NOT EDIT.

package types

import (
	"github.com/traust-security/traust-sdk/go/v1/enums"
)

type PqcReadiness struct {
	ClockItems        []PqcReadinessClockItemsItem        `json:"clock_items,omitempty"`
	FipsInteraction   *PqcReadinessFipsInteraction        `json:"fips_interaction,omitempty"`
	Flags             PqcReadinessFlags                   `json:"flags"`
	Metadata          PqcReadinessMetadata                `json:"metadata"`
	Notes             *string                             `json:"notes,omitempty"`
	ProvenanceSummary PqcReadinessProvenanceSummary       `json:"provenance_summary"`
	ReadinessBucket   *enums.PqcReadinessBucket           `json:"readiness_bucket,omitempty"`
	Remediations      []PqcReadinessRemediationsItem      `json:"remediations,omitempty"`
	RuntimeEvidence   *PqcReadinessRuntimeEvidence        `json:"runtime_evidence,omitempty"`
	Scores            PqcReadinessScores                  `json:"scores"`
	ServerSideCaveats []PqcReadinessServerSideCaveatsItem `json:"server_side_caveats,omitempty"`
	Title             string                              `json:"title"`
}

type Domain struct {
	AssessableChecks *int               `json:"assessable_checks,omitempty"`
	Checks           []DomainChecksItem `json:"checks"`
	Score            float64            `json:"score"`
}

type DomainChecksItem struct {
	CryptoGovernance *DomainChecksItemCryptoGovernance `json:"crypto_governance,omitempty"`
	FactIds          []string                          `json:"fact_ids,omitempty"`
	Id               string                            `json:"id"`
	Points           *float64                          `json:"points,omitempty"`
	Rationale        *string                           `json:"rationale,omitempty"`
	Result           enums.IsolationCheckResult        `json:"result"`
}

type DomainChecksItemCryptoGovernance struct {
	Class            *enums.CryptoGovernanceClass `json:"class,omitempty"`
	DetectionFacts   []string                     `json:"detection_facts,omitempty"`
	EvaluationTarget *string                      `json:"evaluation_target,omitempty"`
	Governor         *string                      `json:"governor,omitempty"`
}

type PqcReadinessClockItemsItem struct {
	BlastRadius       *enums.PqcBlastRadius    `json:"blast_radius,omitempty"`
	DeprecatedAfter   interface{}              `json:"deprecated_after,omitempty"`
	DisallowedAfter   interface{}              `json:"disallowed_after"`
	FactIds           []string                 `json:"fact_ids"`
	Primitive         string                   `json:"primitive"`
	RemediationEffort *enums.RemediationEffort `json:"remediation_effort,omitempty"`
}

type PqcReadinessFipsInteraction struct {
	FactIds   []string                 `json:"fact_ids"`
	Rationale *string                  `json:"rationale,omitempty"`
	Verdict   enums.PqcFipsInteraction `json:"verdict"`
}

type PqcReadinessFlags struct {
	Has2030ClockItems           bool `json:"has_2030_clock_items"`
	HndlPriority                bool `json:"hndl_priority"`
	RuntimeVerificationRequired bool `json:"runtime_verification_required"`
}

type PqcReadinessMetadata struct {
	AssessedAt      *string                           `json:"assessed_at,omitempty"`
	AssessmentBasis enums.PqcReadinessAssessmentBasis `json:"assessment_basis"`
	CbomRef         interface{}                       `json:"cbom_ref,omitempty"`
	Commit          interface{}                       `json:"commit,omitempty"`
	FactsRef        *string                           `json:"facts_ref,omitempty"`
	Repository      string                            `json:"repository"`
	Tool            PqcReadinessMetadataTool          `json:"tool"`
}

type PqcReadinessMetadataTool struct {
	AdapterVersion *string     `json:"adapter_version,omitempty"`
	BinarySha256   interface{} `json:"binary_sha256,omitempty"`
	PqcScanCommit  string      `json:"pqc_scan_commit"`
	RulesSha256    string      `json:"rules_sha256"`
}

type PqcReadinessProvenanceSummary struct {
	Counts   map[string]int              `json:"counts"`
	Dominant enums.PqcDominantProvenance `json:"dominant"`
}

type PqcReadinessRemediationsItem struct {
	Action            string                       `json:"action"`
	BlastRadius       *enums.PqcBlastRadius        `json:"blast_radius,omitempty"`
	BlockedOn         interface{}                  `json:"blocked_on,omitempty"`
	Category          enums.PqcRemediationCategory `json:"category"`
	Deadline          interface{}                  `json:"deadline,omitempty"`
	Details           interface{}                  `json:"details,omitempty"`
	FactIds           []string                     `json:"fact_ids,omitempty"`
	Id                string                       `json:"id"`
	Locations         []string                     `json:"locations,omitempty"`
	Recipe            interface{}                  `json:"recipe,omitempty"`
	RemediationEffort *enums.RemediationEffort     `json:"remediation_effort,omitempty"`
	Target            interface{}                  `json:"target,omitempty"`
}

type PqcReadinessRuntimeEvidence struct {
	ClosedRuntimeVerification *bool    `json:"closed_runtime_verification,omitempty"`
	PqcCaps                   []string `json:"pqc_caps,omitempty"`
	RuntimeConfirmedAt        *string  `json:"runtime_confirmed_at,omitempty"`
	StalenessWindowDays       *int     `json:"staleness_window_days,omitempty"`
	ValidationReportRef       *string  `json:"validation_report_ref,omitempty"`
}

type PqcReadinessScores struct {
	AGIL    Domain  `json:"AGIL"`
	HNDL    Domain  `json:"HNDL"`
	PQCA    Domain  `json:"PQCA"`
	VULN    Domain  `json:"VULN"`
	Overall float64 `json:"overall"`
}

type PqcReadinessServerSideCaveatsItem struct {
	CaveatType enums.PqcCaveatType `json:"caveat_type"`
	FactIds    []string            `json:"fact_ids"`
	Rationale  *string             `json:"rationale,omitempty"`
}
