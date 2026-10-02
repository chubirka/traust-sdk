// Code generated from traust-contracts v0.48.0. DO NOT EDIT.

package types

import (
	"github.com/traust-security/traust-sdk/go/v1/enums"
)

type ThreatModel struct {
	Assets           []Asset               `json:"assets,omitempty"`
	AttackScenarios  []AttackScenario      `json:"attack_scenarios,omitempty"`
	Deprioritized    []DeprioritizedThreat `json:"deprioritized,omitempty"`
	EntryPoints      []EntryPoint          `json:"entry_points,omitempty"`
	Mitigations      []Mitigation          `json:"mitigations,omitempty"`
	OpenQuestions    []string              `json:"open_questions,omitempty"`
	Provenance       Provenance            `json:"provenance"`
	SubjectId        *string               `json:"subject_id,omitempty"`
	System           string                `json:"system"`
	SystemContext    *string               `json:"system_context,omitempty"`
	TenantBoundaries []TenantBoundary      `json:"tenant_boundaries,omitempty"`
	Threats          []Threat              `json:"threats"`
	UpdateHistory    []HistoryEntry        `json:"update_history,omitempty"`
}

type Asset struct {
	Asset           string              `json:"asset"`
	Description     string              `json:"description"`
	ExampleRecords  *string             `json:"example_records,omitempty"`
	RegulatoryScope *string             `json:"regulatory_scope,omitempty"`
	Sensitivity     enums.ChainSeverity `json:"sensitivity"`
}

type AttackScenario struct {
	Id     string   `json:"id"`
	Steps  []string `json:"steps"`
	Threat *string  `json:"threat,omitempty"`
}

type DeprioritizedThreat struct {
	Reason string `json:"reason"`
	Threat string `json:"threat"`
}

type EntryPoint struct {
	Description     string `json:"description"`
	EntryPoint      string `json:"entry_point"`
	ReachableAssets string `json:"reachable_assets"`
	TrustBoundary   string `json:"trust_boundary"`
}

type HistoryEntry struct {
	Changes string `json:"changes"`
	Date    string `json:"date"`
	Reason  string `json:"reason"`
}

type Mitigation struct {
	ClosesClass enums.MitigationClosesClass `json:"closes_class"`
	Effort      enums.MitigationEffort      `json:"effort"`
	Mitigation  string                      `json:"mitigation"`
	ThreatIds   []string                    `json:"threat_ids"`
}

type OwaspRiskRating struct {
	Impact     OwaspRiskRatingImpact     `json:"impact"`
	Likelihood OwaspRiskRatingLikelihood `json:"likelihood"`
	Method     interface{}               `json:"method"`
	Rationale  map[string]string         `json:"rationale,omitempty"`
	Severity   enums.RiskRatingBand      `json:"severity"`
}

type OwaspRiskRatingImpact struct {
	Basis     enums.OwaspImpactBasis         `json:"basis"`
	Business  *OwaspRiskRatingImpactBusiness `json:"business,omitempty"`
	Level     enums.InterfaceComplexity      `json:"level"`
	Score     float64                        `json:"score"`
	Technical OwaspRiskRatingImpactTechnical `json:"technical"`
}

type OwaspRiskRatingImpactBusiness struct {
	Financial     int `json:"financial"`
	NonCompliance int `json:"non_compliance"`
	Privacy       int `json:"privacy"`
	Reputation    int `json:"reputation"`
}

type OwaspRiskRatingImpactTechnical struct {
	Accountability  int `json:"accountability"`
	Availability    int `json:"availability"`
	Confidentiality int `json:"confidentiality"`
	Integrity       int `json:"integrity"`
}

type OwaspRiskRatingLikelihood struct {
	Factors OwaspRiskRatingLikelihoodFactors `json:"factors"`
	Level   enums.InterfaceComplexity        `json:"level"`
	Score   float64                          `json:"score"`
}

type OwaspRiskRatingLikelihoodFactors struct {
	Awareness          int `json:"awareness"`
	EaseOfDiscovery    int `json:"ease_of_discovery"`
	EaseOfExploit      int `json:"ease_of_exploit"`
	IntrusionDetection int `json:"intrusion_detection"`
	Motive             int `json:"motive"`
	Opportunity        int `json:"opportunity"`
	PopulationSize     int `json:"population_size"`
	SkillLevel         int `json:"skill_level"`
}

type Provenance struct {
	Date           string                `json:"date"`
	HarnessVersion *string               `json:"harness_version,omitempty"`
	Inputs         *string               `json:"inputs,omitempty"`
	Mode           enums.ThreatModelMode `json:"mode"`
	Owner          *string               `json:"owner,omitempty"`
	Target         string                `json:"target"`
}

type TenantBoundary struct {
	Authentication     *string                    `json:"authentication,omitempty"`
	BoundaryId         string                     `json:"boundary_id"`
	Complexity         *enums.InterfaceComplexity `json:"complexity,omitempty"`
	Connectivity       *string                    `json:"connectivity,omitempty"`
	Encryption         *string                    `json:"encryption,omitempty"`
	Exposure           enums.InterfaceExposure    `json:"exposure"`
	Hygiene            *string                    `json:"hygiene,omitempty"`
	Interface          string                     `json:"interface"`
	IsolationReviewRef *string                    `json:"isolation_review_ref,omitempty"`
	Kind               enums.InterfaceKind        `json:"kind"`
	Privilege          *string                    `json:"privilege,omitempty"`
	ThreatIds          []string                   `json:"threat_ids,omitempty"`
}

type Threat struct {
	Actor               []enums.ThreatActor        `json:"actor"`
	Asset               *string                    `json:"asset,omitempty"`
	AttackRefs          []string                   `json:"attack_refs,omitempty"`
	Controls            *string                    `json:"controls,omitempty"`
	Evidence            []string                   `json:"evidence,omitempty"`
	Id                  string                     `json:"id"`
	Impact              *enums.ThreatImpact        `json:"impact,omitempty"`
	IsolationDimensions []enums.IsolationDimension `json:"isolation_dimensions,omitempty"`
	Likelihood          *enums.ThreatLikelihood    `json:"likelihood,omitempty"`
	RiskRating          *OwaspRiskRating           `json:"risk_rating,omitempty"`
	Status              enums.ThreatStatus         `json:"status"`
	Surface             *string                    `json:"surface,omitempty"`
	Threat              string                     `json:"threat"`
}
