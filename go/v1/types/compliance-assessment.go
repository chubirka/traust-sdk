// Code generated from traust-contracts v0.47.0. DO NOT EDIT.

package types

import (
	"github.com/traust-security/traust-sdk/go/v1/enums"
)

type ComplianceAssessment struct {
	Coverage map[string]ComplianceAssessmentCoverageEntry `json:"coverage"`
	Metadata ComplianceAssessmentMetadata                 `json:"metadata"`
	Results  []ComplianceAssessmentResultsItem            `json:"results"`
}

type ComplianceAssessmentCoverageEntry struct {
	Deterministic  int `json:"deterministic"`
	EvidenceReview int `json:"evidence_review"`
	NotApplicable  int `json:"not_applicable"`
	NotAssessed    int `json:"not_assessed"`
	NotSatisfied   int `json:"not_satisfied"`
	Organizational int `json:"organizational"`
	Satisfied      int `json:"satisfied"`
	TotalInScope   int `json:"total_in_scope"`
}

type ComplianceAssessmentMetadata struct {
	Artifact          interface{}                                         `json:"artifact"`
	CollectorVersions map[string]string                                   `json:"collector_versions,omitempty"`
	Frameworks        []ComplianceAssessmentMetadataFrameworksItem        `json:"frameworks"`
	GeneratedAt       string                                              `json:"generated_at"`
	HarnessVersion    string                                              `json:"harness_version"`
	OrgParametersHash *string                                             `json:"org_parameters_hash,omitempty"`
	OwnerAttestations []ComplianceAssessmentMetadataOwnerAttestationsItem `json:"owner_attestations,omitempty"`
	RegistryHash      string                                              `json:"registry_hash"`
	Target            ComplianceAssessmentMetadataTarget                  `json:"target"`
}

type ComplianceAssessmentMetadataFrameworksItem struct {
	Caveat  *string                   `json:"caveat,omitempty"`
	Id      enums.ComplianceFramework `json:"id"`
	Profile *string                   `json:"profile,omitempty"`
}

type ComplianceAssessmentMetadataOwnerAttestationsItem struct {
	AppliesTo    []string `json:"applies_to,omitempty"`
	AttestedAt   string   `json:"attested_at"`
	AttestedBy   string   `json:"attested_by"`
	Id           string   `json:"id"`
	LdapVerified bool     `json:"ldap_verified"`
	Statement    string   `json:"statement"`
	Topic        string   `json:"topic"`
}

type ComplianceAssessmentMetadataTarget struct {
	CdeBoundary            *string                                  `json:"cde_boundary,omitempty"`
	Environment            *string                                  `json:"environment,omitempty"`
	Kind                   enums.ComplianceTargetKind               `json:"kind"`
	PersonalDataStores     []string                                 `json:"personal_data_stores,omitempty"`
	Product                *string                                  `json:"product,omitempty"`
	Repos                  []string                                 `json:"repos,omitempty"`
	Scope                  *ComplianceAssessmentMetadataTargetScope `json:"scope,omitempty"`
	ScopeBindingMode       *string                                  `json:"scope_binding_mode,omitempty"`
	SnapshotId             *string                                  `json:"snapshot_id,omitempty"`
	TrustServiceCategories []enums.TrustServiceCategory             `json:"trust_service_categories,omitempty"`
}

type ComplianceAssessmentMetadataTargetScope struct {
	Boundary     string                                                `json:"boundary"`
	DeclaredAt   string                                                `json:"declared_at"`
	DeclaredBy   string                                                `json:"declared_by"`
	Draft        bool                                                  `json:"draft"`
	Excluded     []ComplianceAssessmentMetadataTargetScopeExcludedItem `json:"excluded,omitempty"`
	RegistryHash interface{}                                           `json:"registry_hash,omitempty"`
	ResolvesVia  enums.ComplianceTargetResolvesVia                     `json:"resolves_via"`
}

type ComplianceAssessmentMetadataTargetScopeExcludedItem struct {
	Reason string `json:"reason"`
	Repo   string `json:"repo"`
}

type ComplianceAssessmentResultsItem struct {
	CheckId        *string                                        `json:"check_id,omitempty"`
	Classification enums.ComplianceControlClassification          `json:"classification"`
	ControlId      string                                         `json:"control_id"`
	Evidence       []ComplianceAssessmentResultsItemEvidenceItem  `json:"evidence,omitempty"`
	Framework      string                                         `json:"framework"`
	NPassAgreement *ComplianceAssessmentResultsItemNPassAgreement `json:"n_pass_agreement,omitempty"`
	Narrative      *string                                        `json:"narrative,omitempty"`
	Override       *ComplianceAssessmentResultsItemOverride       `json:"override,omitempty"`
	Reason         *string                                        `json:"reason,omitempty"`
	Title          *string                                        `json:"title,omitempty"`
	Verdict        enums.ComplianceVerdict                        `json:"verdict"`
	VerdictSource  enums.ComplianceVerdictSource                  `json:"verdict_source"`
}

type ComplianceAssessmentResultsItemEvidenceItem struct {
	Excerpt *string                      `json:"excerpt,omitempty"`
	Kind    enums.ComplianceEvidenceKind `json:"kind"`
	Locator string                       `json:"locator"`
	Sha256  string                       `json:"sha256"`
}

type ComplianceAssessmentResultsItemNPassAgreement struct {
	Agreed bool `json:"agreed"`
	Passes int  `json:"passes"`
}

type ComplianceAssessmentResultsItemOverride struct {
	By                     string  `json:"by"`
	Date                   string  `json:"date"`
	OverriddenCheckVerdict *string `json:"overridden_check_verdict,omitempty"`
	Rationale              string  `json:"rationale"`
}
