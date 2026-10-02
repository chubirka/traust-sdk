// Code generated from traust-contracts v0.48.0. DO NOT EDIT.

package types

import (
	"github.com/traust-security/traust-sdk/go/v1/enums"
)

type Remediation struct {
	Checks         []Check             `json:"checks"`
	Evidence       []PatchEvidence     `json:"evidence,omitempty"`
	Footer         *string             `json:"footer,omitempty"`
	Fork           Fork                `json:"fork"`
	Metadata       RemediationMetadata `json:"metadata"`
	Notes          *string             `json:"notes,omitempty"`
	Patch          Patch               `json:"patch"`
	PullRequest    *PullRequest        `json:"pull_request,omitempty"`
	Revalidation   *Revalidation       `json:"revalidation,omitempty"`
	SourceFindings []SourceFinding     `json:"source_findings"`
	Summary        RemediationSummary  `json:"summary"`
	Title          string              `json:"title"`
}

type Check struct {
	Command         string                        `json:"command"`
	DurationSeconds *float64                      `json:"duration_seconds,omitempty"`
	LogPath         *string                       `json:"log_path,omitempty"`
	Name            string                        `json:"name"`
	Outcome         enums.RemediationCheckOutcome `json:"outcome"`
	Summary         *string                       `json:"summary,omitempty"`
}

type Fork struct {
	BaseCommit           *string              `json:"base_commit,omitempty"`
	BaseRef              string               `json:"base_ref"`
	FixBranch            string               `json:"fix_branch"`
	FixCommit            *string              `json:"fix_commit,omitempty"`
	Host                 *enums.ForkHost      `json:"host,omitempty"`
	SyncedFromUpstreamAt *string              `json:"synced_from_upstream_at,omitempty"`
	UpstreamRemote       *string              `json:"upstream_remote,omitempty"`
	Url                  string               `json:"url"`
	Visibility           enums.ForkVisibility `json:"visibility"`
}

type Patch struct {
	BehaviourChange *string                 `json:"behaviour_change,omitempty"`
	DiffPath        *string                 `json:"diff_path,omitempty"`
	DiffSha256      *string                 `json:"diff_sha256,omitempty"`
	Diffstat        PatchDiffstat           `json:"diffstat"`
	FilesChanged    []PatchFilesChangedItem `json:"files_changed"`
	Rationale       string                  `json:"rationale"`
	ResidualRisk    *string                 `json:"residual_risk,omitempty"`
	Strategy        enums.FixStrategy       `json:"strategy"`
	TestsAdded      []string                `json:"tests_added,omitempty"`
}

type PatchDiffstat struct {
	Additions int `json:"additions"`
	Deletions int `json:"deletions"`
	Files     int `json:"files"`
}

type PatchEvidence struct {
	BaseObservation    *string                 `json:"base_observation,omitempty"`
	Command            *string                 `json:"command,omitempty"`
	DeterministicSteps *string                 `json:"deterministic_steps,omitempty"`
	Kind               enums.PatchEvidenceKind `json:"kind"`
	LogPath            *string                 `json:"log_path,omitempty"`
	Outcome            string                  `json:"outcome"`
	PatchedObservation *string                 `json:"patched_observation,omitempty"`
	Tool               *string                 `json:"tool,omitempty"`
}

type PatchFilesChangedItem struct {
	Additions  *int                 `json:"additions,omitempty"`
	ChangeType enums.FileChangeType `json:"change_type"`
	Deletions  *int                 `json:"deletions,omitempty"`
	Hunks      *int                 `json:"hunks,omitempty"`
	Path       string               `json:"path"`
}

type PullRequest struct {
	BaseBranch *string                 `json:"base_branch,omitempty"`
	Number     *int                    `json:"number,omitempty"`
	Reviewers  []string                `json:"reviewers,omitempty"`
	State      *enums.PullRequestState `json:"state,omitempty"`
	Target     enums.PullRequestTarget `json:"target"`
	Url        string                  `json:"url"`
}

type RemediationMetadata struct {
	AuditedCommit  *string  `json:"audited_commit,omitempty"`
	Date           string   `json:"date"`
	HarnessVersion string   `json:"harness_version"`
	JiraKeys       []string `json:"jira_keys,omitempty"`
	Language       *string  `json:"language,omitempty"`
	LogicalProduct string   `json:"logical_product"`
	Operator       *string  `json:"operator,omitempty"`
	Repository     string   `json:"repository"`
}

type RemediationSummary struct {
	ChecksPassed      int                     `json:"checks_passed"`
	ChecksTotal       int                     `json:"checks_total"`
	FindingsAddressed *int                    `json:"findings_addressed,omitempty"`
	ReadyForReview    *bool                   `json:"ready_for_review,omitempty"`
	Status            enums.RemediationStatus `json:"status"`
}

type Revalidation struct {
	AfterVerdict         *enums.ValidationVerdict            `json:"after_verdict,omitempty"`
	BeforeVerdict        *enums.RemediationValidationVerdict `json:"before_verdict,omitempty"`
	Fixed                *bool                               `json:"fixed,omitempty"`
	ImageRef             *string                             `json:"image_ref,omitempty"`
	Method               *enums.RevalidationMethod           `json:"method,omitempty"`
	Performed            bool                                `json:"performed"`
	ValidationReportPath *string                             `json:"validation_report_path,omitempty"`
}

type SourceFinding struct {
	AuditReportPath      *string                             `json:"audit_report_path,omitempty"`
	Cwes                 []string                            `json:"cwes"`
	FindingRef           string                              `json:"finding_ref"`
	Locations            []Location                          `json:"locations"`
	Severity             enums.Severity                      `json:"severity"`
	Title                string                              `json:"title"`
	TriageConfidence     *float64                            `json:"triage_confidence,omitempty"`
	TriageReportPath     *string                             `json:"triage_report_path,omitempty"`
	ValidationReportPath *string                             `json:"validation_report_path,omitempty"`
	ValidationVerdict    *enums.RemediationValidationVerdict `json:"validation_verdict,omitempty"`
}
