package storage

import (
	"errors"
	"fmt"
)

var (
	ErrNilDatabase          = errors.New("storage database is nil")
	ErrNoResolver           = errors.New("storage resolver is not configured")
	ErrUnsupportedDatabase  = errors.New("storage database is unsupported")
	ErrIncompatibleDatabase = errors.New("storage database is incompatible")
	ErrIncompatibleRevision = errors.New("storage revision requires explicit migration")
	ErrScopeRequired        = errors.New("storage scope is required")
	ErrSubjectIDRequired    = errors.New("storage subject ID is required")
	ErrRunIDRequired        = errors.New("storage run ID is required")
	ErrLayerIDRequired      = errors.New("storage layer ID is required")
	ErrInvalidIdentifier    = errors.New("storage identifier is invalid")
	ErrUnknownArtifact      = errors.New("storage artifact type is unknown")
	ErrNotFound             = errors.New("storage artifact not found")
	ErrBindingNotFound      = errors.New("storage artifact binding not found")
	ErrArtifactTypeMismatch = errors.New("storage artifact type mismatch")
	ErrBindingMismatch      = errors.New("storage artifact binding context mismatch")
	ErrEvidenceCorrupt      = errors.New("storage evidence digest mismatch")
	ErrRoleNotAllowed       = errors.New("storage artifact role is not allowed")
	ErrInvalidReference     = errors.New("storage artifact reference is invalid")
)

type Operation string

const (
	OperationInit  Operation = "init"
	OperationSave  Operation = "save"
	OperationRead  Operation = "read"
	OperationQuery Operation = "query"
)

type Phase string

const (
	PhaseInput     Phase = "input"
	PhaseConnect   Phase = "connect"
	PhaseDialect   Phase = "dialect"
	PhaseBegin     Phase = "begin"
	PhaseLock      Phase = "lock"
	PhaseRevision  Phase = "revision"
	PhaseBootstrap Phase = "bootstrap"
	PhaseValidate  Phase = "validate"
	PhaseDecode    Phase = "decode"
	PhaseEvidence  Phase = "evidence"
	PhaseBinding   Phase = "binding"
	PhaseProject   Phase = "project"
	PhaseScope     Phase = "scope"
	PhaseRead      Phase = "read"
	PhaseCommit    Phase = "commit"
)

// Error identifies a safe operation phase while preserving its cause for errors.Is and errors.As.
type Error struct {
	Operation Operation
	Phase     Phase
	Err       error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("storage %s failed during %s", e.Operation, e.Phase)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func wrap(operation Operation, phase Phase, err error) error {
	return &Error{Operation: operation, Phase: phase, Err: err}
}

func projectionError(projection projectionName, field projectionField, err error) error {
	return wrap(OperationSave, PhaseProject, fmt.Errorf("%s.%s: %w", projection, field, err))
}
