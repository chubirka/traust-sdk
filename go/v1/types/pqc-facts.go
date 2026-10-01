// Code generated from traust-contracts v0.47.0. DO NOT EDIT.

package types

import (
	"github.com/traust-security/traust-sdk/go/v1/enums"
)

type PqcFacts struct {
	Artifact   interface{}      `json:"artifact"`
	Coverage   PqcFactsCoverage `json:"coverage"`
	Facts      []Fact           `json:"facts"`
	Repository string           `json:"repository"`
	Stamps     PqcFactsStamps   `json:"stamps"`
	Summary    PqcFactsSummary  `json:"summary"`
}

type Fact struct {
	CapabilityHint *string            `json:"capability_hint,omitempty"`
	Confidence     interface{}        `json:"confidence,omitempty"`
	Detail         string             `json:"detail"`
	FactId         string             `json:"fact_id"`
	File           string             `json:"file"`
	FindingId      interface{}        `json:"finding_id,omitempty"`
	FipsMode       *bool              `json:"fips_mode,omitempty"`
	Ir8547         FactIr8547         `json:"ir8547"`
	Line           interface{}        `json:"line"`
	Match          *string            `json:"match,omitempty"`
	PathClass      enums.PqcPathClass `json:"path_class"`
	PqcCapable     *bool              `json:"pqc_capable,omitempty"`
	ProvenanceHint string             `json:"provenance_hint"`
	Provider       *string            `json:"provider,omitempty"`
	Risk           interface{}        `json:"risk,omitempty"`
	RuleId         string             `json:"rule_id"`
	Severity       interface{}        `json:"severity,omitempty"`
}

type FactIr8547 struct {
	Clock          interface{} `json:"clock"`
	MatchedPrefix  *string     `json:"matched_prefix,omitempty"`
	Qclass         string      `json:"qclass"`
	QclassResolved *string     `json:"qclass_resolved,omitempty"`
	Usage          string      `json:"usage"`
}

type FactIr8547Clock struct {
	DeprecatedAfter interface{} `json:"deprecated_after,omitempty"`
	DisallowedAfter interface{} `json:"disallowed_after,omitempty"`
	StatusNow       *string     `json:"status_now,omitempty"`
}

type PqcFactsCoverage struct {
	AssessmentBasis           enums.PqcFactsAssessmentBasis `json:"assessment_basis"`
	NoCryptoDetectedAssertion *string                       `json:"no_crypto_detected_assertion,omitempty"`
	RulesInPack               interface{}                   `json:"rules_in_pack"`
	ScannedFiles              interface{}                   `json:"scanned_files"`
	SkippedFiles              interface{}                   `json:"skipped_files"`
}

type PqcFactsStamps struct {
	AdapterVersion string  `json:"adapter_version"`
	BinarySha256   *string `json:"binary_sha256,omitempty"`
	PqcScanCommit  string  `json:"pqc_scan_commit"`
	RulesSha256    string  `json:"rules_sha256"`
}

type PqcFactsSummary struct {
	ByPathClass      map[string]int `json:"by_path_class"`
	ByProvenanceHint map[string]int `json:"by_provenance_hint"`
	ByQclass         map[string]int `json:"by_qclass"`
	ByRule           map[string]int `json:"by_rule"`
}
