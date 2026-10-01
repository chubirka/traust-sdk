// Code generated from traust-contracts v0.47.0. DO NOT EDIT.

package types

import (
	"github.com/traust-security/traust-sdk/go/v1/enums"
)

type RiskRatingMethodology struct {
	Bands              []enums.RiskRatingBand                  `json:"bands"`
	BucketThresholds   RiskRatingMethodologyBucketThresholds   `json:"bucket_thresholds"`
	Documentation      *string                                 `json:"documentation,omitempty"`
	Fallback           RiskRatingMethodologyFallback           `json:"fallback"`
	ImpactFactors      RiskRatingMethodologyImpactFactors      `json:"impact_factors"`
	LikelihoodFactors  RiskRatingMethodologyLikelihoodFactors  `json:"likelihood_factors"`
	Matrix             RiskRatingMethodologyMatrix             `json:"matrix"`
	Methodology        interface{}                             `json:"methodology"`
	MethodologyVersion string                                  `json:"methodology_version"`
	Schema             *string                                 `json:"schema,omitempty"`
	Source             string                                  `json:"source"`
	ThreatIntelFactor  *RiskRatingMethodologyThreatIntelFactor `json:"threat_intel_factor,omitempty"`
}

type CiaMap struct {
	H float64 `json:"H"`
	L float64 `json:"L"`
	N float64 `json:"N"`
}

type MatrixRow struct {
	HIGH   enums.RiskRatingBand `json:"HIGH"`
	LOW    enums.RiskRatingBand `json:"LOW"`
	MEDIUM enums.RiskRatingBand `json:"MEDIUM"`
}

type RiskRatingMethodologyBucketThresholds struct {
	HighMin   float64 `json:"high_min"`
	MediumMin float64 `json:"medium_min"`
}

type RiskRatingMethodologyFallback struct {
	DefaultLikelihood float64                                     `json:"default_likelihood"`
	SeverityImpact    RiskRatingMethodologyFallbackSeverityImpact `json:"severity_impact"`
}

type RiskRatingMethodologyFallbackSeverityImpact struct {
	Critical      float64 `json:"critical"`
	High          float64 `json:"high"`
	Informational float64 `json:"informational"`
	Low           float64 `json:"low"`
	Medium        float64 `json:"medium"`
}

type RiskRatingMethodologyImpactFactors struct {
	A CiaMap `json:"A"`
	C CiaMap `json:"C"`
	I CiaMap `json:"I"`
}

type RiskRatingMethodologyLikelihoodFactors struct {
	AC map[string]float64 `json:"AC"`
	AV map[string]float64 `json:"AV"`
	PR map[string]float64 `json:"PR"`
	UI map[string]float64 `json:"UI"`
}

type RiskRatingMethodologyMatrix struct {
	HIGH   MatrixRow `json:"HIGH"`
	LOW    MatrixRow `json:"LOW"`
	MEDIUM MatrixRow `json:"MEDIUM"`
}

type RiskRatingMethodologyThreatIntelFactor struct {
	Description *string                                               `json:"description,omitempty"`
	EpssBands   []RiskRatingMethodologyThreatIntelFactorEpssBandsItem `json:"epss_bands"`
	KevScore    float64                                               `json:"kev_score"`
}

type RiskRatingMethodologyThreatIntelFactorEpssBandsItem struct {
	MinEpss float64 `json:"min_epss"`
	Score   float64 `json:"score"`
}
