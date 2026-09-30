// Code generated from traust-contracts v0.44.0. DO NOT EDIT.

package types

import (
	"github.com/traust-security/traust-sdk/go/v1/enums"
)

type PqcBlockers struct {
	Artifact           interface{}                         `json:"artifact"`
	ExecutiveSummary   PqcBlockersExecutiveSummary         `json:"executive_summary"`
	Findings           []Finding                           `json:"findings"`
	FindingsSummary    []PqcBlockersFindingsSummaryItem    `json:"findings_summary"`
	Metadata           PqcBlockersMetadata                 `json:"metadata"`
	RemediationRoadmap []PqcBlockersRemediationRoadmapItem `json:"remediation_roadmap"`
	SeverityCriteria   []PqcBlockersSeverityCriteriaItem   `json:"severity_criteria"`
	Title              string                              `json:"title"`
}

type Finding struct {
	Category          interface{}              `json:"category"`
	Cwes              []string                 `json:"cwes"`
	Description       string                   `json:"description"`
	Id                string                   `json:"id"`
	Locations         []FindingLocationsItem   `json:"locations"`
	PqcClassification enums.PqcClassification  `json:"pqc_classification"`
	Remediation       string                   `json:"remediation"`
	RemediationEffort *enums.RemediationEffort `json:"remediation_effort,omitempty"`
	Severity          enums.Severity           `json:"severity"`
	Title             string                   `json:"title"`
	ValidationStatus  interface{}              `json:"validation_status"`
}

type FindingLocationsItem struct {
	Lines *string `json:"lines,omitempty"`
	Path  string  `json:"path"`
}

type PqcBlockersExecutiveSummary struct {
	Prose          string                 `json:"prose"`
	SeverityCounts map[string]interface{} `json:"severity_counts"`
}

type PqcBlockersFindingsSummaryItem struct {
	Count      int            `json:"count"`
	FindingIds []string       `json:"finding_ids"`
	Severity   enums.Severity `json:"severity"`
}

type PqcBlockersMetadata struct {
	Additional  *PqcBlockersMetadataAdditional `json:"additional,omitempty"`
	Commit      interface{}                    `json:"commit,omitempty"`
	Date        string                         `json:"date"`
	Framework   *string                        `json:"framework,omitempty"`
	Methodology *string                        `json:"methodology,omitempty"`
	Repository  string                         `json:"repository"`
	Scope       string                         `json:"scope"`
}

type PqcBlockersMetadataAdditional struct {
	AdapterVersion       *string  `json:"adapter_version,omitempty"`
	ExcludedRemediations []string `json:"excluded_remediations"`
	HarnessVersion       *string  `json:"harness_version,omitempty"`
	ReadinessStatus      *string  `json:"readiness_status,omitempty"`
	SourceArtifact       string   `json:"source_artifact"`
	WhoSetsTls           string   `json:"who_sets_tls"`
}

type PqcBlockersRemediationRoadmapItem struct {
	Action    string   `json:"action"`
	Addresses []string `json:"addresses"`
	Priority  string   `json:"priority"`
}

type PqcBlockersSeverityCriteriaItem struct {
	Definition string         `json:"definition"`
	Level      enums.Severity `json:"level"`
}
