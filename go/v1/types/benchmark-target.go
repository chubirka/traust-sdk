// Code generated from traust-contracts v0.47.0. DO NOT EDIT.

package types

import (
	"github.com/traust-security/traust-sdk/go/v1/enums"
)

type BenchmarkTarget struct {
	Targets []BenchmarkTargetTargetsItem `json:"targets"`
	Updated string                       `json:"updated"`
	Version int                          `json:"version"`
}

type BenchmarkTargetTargetsItem struct {
	Admitted   bool                                     `json:"admitted"`
	AdmittedAt interface{}                              `json:"admitted_at,omitempty"`
	AdmittedBy interface{}                              `json:"admitted_by,omitempty"`
	Embargo    *enums.BenchmarkTargetEmbargo            `json:"embargo,omitempty"`
	Evidence   *BenchmarkTargetTargetsItemEvidence      `json:"evidence,omitempty"`
	Expected   []BenchmarkTargetTargetsItemExpectedItem `json:"expected"`
	FixCommit  interface{}                              `json:"fix_commit,omitempty"`
	HeldOut    *bool                                    `json:"held_out,omitempty"`
	Id         string                                   `json:"id"`
	Injection  *BenchmarkTargetTargetsItemInjection     `json:"injection,omitempty"`
	Language   interface{}                              `json:"language,omitempty"`
	Notes      *string                                  `json:"notes,omitempty"`
	PreFixSha  interface{}                              `json:"pre_fix_sha,omitempty"`
	Provenance enums.BenchmarkTargetProvenance          `json:"provenance"`
	RepoUrl    string                                   `json:"repo_url"`
}

type BenchmarkTargetTargetsItemEvidence struct {
	Excerpt *string                           `json:"excerpt,omitempty"`
	Kind    enums.BenchmarkTargetEvidenceKind `json:"kind"`
	Ref     string                            `json:"ref"`
}

type BenchmarkTargetTargetsItemExpectedItem struct {
	Cwes          []string       `json:"cwes"`
	Fingerprint   interface{}    `json:"fingerprint,omitempty"`
	Paths         []string       `json:"paths"`
	Severity      enums.Severity `json:"severity"`
	SourceFinding *string        `json:"source_finding,omitempty"`
	Title         *string        `json:"title,omitempty"`
}

type BenchmarkTargetTargetsItemInjection struct {
	Class  enums.BenchmarkTargetInjectionClass `json:"class"`
	Tokens []string                            `json:"tokens"`
}
