// Code generated from traust-contracts v0.46.0. DO NOT EDIT.

package types

import (
	"github.com/traust-security/traust-sdk/go/v1/enums"
)

type Layer struct {
	BaselineClaims map[string]string `json:"baseline_claims,omitempty"`
	Events         []Event           `json:"events"`
	Metadata       LayerMetadata     `json:"metadata"`
	NeedsReview    []ReviewItem      `json:"needs_review"`
}

type Actor struct {
	DisplayName      *string         `json:"display_name,omitempty"`
	EmployeeStatus   *string         `json:"employee_status,omitempty"`
	Identity         *string         `json:"identity,omitempty"`
	IdentityIssuer   *string         `json:"identity_issuer,omitempty"`
	IdentityProvider *string         `json:"identity_provider,omitempty"`
	IdentitySubject  *string         `json:"identity_subject,omitempty"`
	IdentityVerified *bool           `json:"identity_verified,omitempty"`
	Kind             enums.ActorKind `json:"kind"`
	LdapVerified     *bool           `json:"ldap_verified,omitempty"`
}

type Disposition struct {
	Embargo    *enums.DispositionEmbargo    `json:"embargo,omitempty"`
	Resolution *enums.DispositionResolution `json:"resolution,omitempty"`
	Severity   *enums.Severity              `json:"severity,omitempty"`
	Validity   *enums.EventValidity         `json:"validity,omitempty"`
}

type Event struct {
	Alias           *EventAlias       `json:"alias,omitempty"`
	AutoAcceptTier  *bool             `json:"auto_accept_tier,omitempty"`
	Disposition     Disposition       `json:"disposition"`
	EventId         string            `json:"event_id"`
	EvidenceGrade   *string           `json:"evidence_grade,omitempty"`
	EvidenceRefs    []string          `json:"evidence_refs,omitempty"`
	Finding         *EventFinding     `json:"finding,omitempty"`
	FindingRef      string            `json:"finding_ref"`
	Fingerprint     *string           `json:"fingerprint,omitempty"`
	FingerprintAlgo *string           `json:"fingerprint_algo,omitempty"`
	HarnessVersion  *string           `json:"harness_version,omitempty"`
	OccurredAt      *string           `json:"occurred_at,omitempty"`
	Rationale       string            `json:"rationale"`
	RecordedAt      string            `json:"recorded_at"`
	Restatement     *EventRestatement `json:"restatement,omitempty"`
	RiskWeight      *EventRiskWeight  `json:"risk_weight,omitempty"`
	Source          EventSource       `json:"source"`
}

type EventAlias struct {
	Confirmed     *bool                `json:"confirmed,omitempty"`
	FromReport    *string              `json:"from_report,omitempty"`
	MatchedBy     enums.AliasMatchedBy `json:"matched_by"`
	NewFindingRef string               `json:"new_finding_ref"`
	Note          *string              `json:"note,omitempty"`
	PathOverlap   *float64             `json:"path_overlap,omitempty"`
	Rejected      *bool                `json:"rejected,omitempty"`
	Similarity    *float64             `json:"similarity,omitempty"`
}

type EventFinding struct {
	Cwes             []string                 `json:"cwes"`
	Description      string                   `json:"description"`
	Id               string                   `json:"id"`
	Locations        []map[string]interface{} `json:"locations"`
	Origin           *string                  `json:"origin,omitempty"`
	Remediation      string                   `json:"remediation"`
	Severity         enums.Severity           `json:"severity"`
	SourceFindings   []string                 `json:"source_findings,omitempty"`
	Title            string                   `json:"title"`
	ValidationStatus *string                  `json:"validation_status,omitempty"`
}

type EventRestatement struct {
	After      interface{}               `json:"after"`
	Authority  EventRestatementAuthority `json:"authority"`
	Before     interface{}               `json:"before"`
	Reason     enums.RestatementReason   `json:"reason"`
	SchemaFrom *string                   `json:"schema_from,omitempty"`
	SchemaTo   *string                   `json:"schema_to,omitempty"`
	Target     enums.RestatementTarget   `json:"target"`
}

type EventRestatementAuthority struct {
	ApprovedBy *string `json:"approved_by,omitempty"`
	Ticket     string  `json:"ticket"`
}

type EventRiskWeight struct {
	Lambda         float64              `json:"lambda"`
	ProfileSource  string               `json:"profile_source"`
	TenancyProfile enums.TenancyProfile `json:"tenancy_profile"`
	WeightsVersion string               `json:"weights_version"`
}

type EventSource struct {
	Actor      Actor            `json:"actor"`
	Ref        string           `json:"ref"`
	ReportedBy *string          `json:"reported_by,omitempty"`
	Type       enums.SourceType `json:"type"`
}

type LayerMetadata struct {
	ArtifactDigests       map[string]string                               `json:"artifact_digests,omitempty"`
	AuditCommit           *string                                         `json:"audit_commit,omitempty"`
	AuditReport           string                                          `json:"audit_report"`
	AuditReportRef        *string                                         `json:"audit_report_ref,omitempty"`
	AuditReportSha256     *string                                         `json:"audit_report_sha256,omitempty"`
	ClaimHashes           map[string]string                               `json:"claim_hashes,omitempty"`
	Created               string                                          `json:"created"`
	ExternalRefs          map[string][]LayerMetadataExternalRefsEntryItem `json:"external_refs,omitempty"`
	FindingAliases        map[string]LayerMetadataFindingAliasesEntry     `json:"finding_aliases,omitempty"`
	HarnessVersion        string                                          `json:"harness_version"`
	LeafFormat            *int                                            `json:"leaf_format,omitempty"`
	MerkleAlgorithm       *string                                         `json:"merkle_algorithm,omitempty"`
	MerkleEpoch           *int                                            `json:"merkle_epoch,omitempty"`
	MerkleRoot            *string                                         `json:"merkle_root,omitempty"`
	MerkleRootSignature   *string                                         `json:"merkle_root_signature,omitempty"`
	MerkleSignatureFormat *int                                            `json:"merkle_signature_format,omitempty"`
	MerkleSigningMethod   *string                                         `json:"merkle_signing_method,omitempty"`
	MerkleSize            *int                                            `json:"merkle_size,omitempty"`
	PreMerkleCheckpoint   *string                                         `json:"pre_merkle_checkpoint,omitempty"`
	Repository            string                                          `json:"repository"`
	Updated               *string                                         `json:"updated,omitempty"`
}

type LayerMetadataExternalRefsEntryItem struct {
	Confidence *enums.ExternalRefConfidence `json:"confidence,omitempty"`
	Id         string                       `json:"id"`
	MatchedOn  *string                      `json:"matched_on,omitempty"`
	StampedAt  *string                      `json:"stamped_at,omitempty"`
	System     enums.ExternalRefSystem      `json:"system"`
	Url        *string                      `json:"url,omitempty"`
}

type LayerMetadataFindingAliasesEntry struct {
	Confirmed   *bool                `json:"confirmed,omitempty"`
	ConfirmedAt *string              `json:"confirmed_at,omitempty"`
	ConfirmedBy *string              `json:"confirmed_by,omitempty"`
	FromReport  *string              `json:"from_report,omitempty"`
	MappedAt    string               `json:"mapped_at"`
	MatchedBy   enums.AliasMatchedBy `json:"matched_by"`
	NewId       string               `json:"new_id"`
	Note        *string              `json:"note,omitempty"`
	PathOverlap *float64             `json:"path_overlap,omitempty"`
	Rejected    *bool                `json:"rejected,omitempty"`
	RejectedAt  *string              `json:"rejected_at,omitempty"`
	RejectedBy  *string              `json:"rejected_by,omitempty"`
	Similarity  *float64             `json:"similarity,omitempty"`
}

type ReviewItem struct {
	Author               string                        `json:"author"`
	QueueReason          *enums.LayerReviewQueueReason `json:"queue_reason,omitempty"`
	QueuedAt             string                        `json:"queued_at"`
	Quote                string                        `json:"quote"`
	ResolutionNote       *string                       `json:"resolution_note,omitempty"`
	SourceRef            string                        `json:"source_ref"`
	Status               enums.ReviewItemStatus        `json:"status"`
	SubmittedBy          *Actor                        `json:"submitted_by,omitempty"`
	SuggestedDisposition *Disposition                  `json:"suggested_disposition,omitempty"`
	SuggestedFindingRef  *string                       `json:"suggested_finding_ref,omitempty"`
}
