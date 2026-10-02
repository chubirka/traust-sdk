package storage

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Binding associates evidence with opaque caller-owned workflow identities.
type Binding struct {
	ScopeID             string  `json:"scope_id,omitempty"`
	SubjectID           *string `json:"subject_id,omitempty"`
	RunID               *string `json:"run_id,omitempty"`
	LayerID             *string `json:"layer_id,omitempty"`
	SupersedesBindingID *string `json:"supersedes_binding_id,omitempty"`
	// Role is a lifecycle role within one context, e.g. a report that is the
	// "baseline" audit or its "cumulative" restatement. Allowed values come
	// from the artifact's profile; it is part of the binding identity.
	Role *string `json:"role,omitempty"`
}

type BindingRecord struct {
	BindingID    string  `json:"binding_id"`
	Digest       string  `json:"digest"`
	ArtifactName string  `json:"artifact_name"`
	Binding      Binding `json:"binding"`
	BoundAt      string  `json:"bound_at"`
	// References are the registered locations of the exact bytes, by
	// registration time then reference.
	References []string `json:"references,omitempty"`
	// ByteSize is the exact length of the evidence the digest names.
	ByteSize int64 `json:"byte_size"`
}

type SaveResult struct {
	Digest       string `json:"digest"`
	BindingID    string `json:"binding_id"`
	AlreadyBound bool   `json:"already_bound"`
}

type bindingRequirements struct {
	subject bool
	run     bool
	layer   bool
	roles   []string
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func normalizedBinding(binding Binding) Binding {
	if binding.ScopeID == "" {
		binding.ScopeID = defaultScopeID
	}
	return binding
}

func validateBinding(binding Binding, requirements bindingRequirements) error {
	if binding.ScopeID == "" {
		return ErrScopeRequired
	}
	if !validBindingText(binding.ScopeID) {
		return ErrInvalidIdentifier
	}
	for _, value := range []*string{
		binding.SubjectID,
		binding.RunID,
		binding.LayerID,
		binding.SupersedesBindingID,
		binding.Role,
	} {
		if value != nil && !validBindingText(*value) {
			return ErrInvalidIdentifier
		}
	}
	if requirements.subject && binding.SubjectID == nil {
		return ErrSubjectIDRequired
	}
	if requirements.run && binding.RunID == nil {
		return ErrRunIDRequired
	}
	if requirements.layer && binding.LayerID == nil {
		return ErrLayerIDRequired
	}
	if binding.Role != nil && !slices.Contains(requirements.roles, *binding.Role) {
		return ErrRoleNotAllowed
	}
	return nil
}

// normalizedReferences validates opaque caller references and drops repeats,
// keeping first-seen order. References are never parsed as URIs.
func normalizedReferences(references []string) ([]string, error) {
	seen := make(map[string]bool, len(references))
	out := make([]string, 0, len(references))
	for _, reference := range references {
		if reference == "" || !validBindingText(reference) {
			return nil, ErrInvalidReference
		}
		if !seen[reference] {
			seen[reference] = true
			out = append(out, reference)
		}
	}
	return out, nil
}

func scopeValue(ids []string) (string, error) {
	if len(ids) == 0 {
		return "", ErrScopeRequired
	}
	for _, id := range ids {
		if id == "" || !validBindingText(id) {
			return "", ErrInvalidIdentifier
		}
	}
	encoded, err := json.Marshal(ids)
	return string(encoded), err
}

func validBindingText(value string) bool {
	return utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}
