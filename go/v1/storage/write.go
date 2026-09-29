package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/traust-security/traust-sdk/go/v1/types"
	"github.com/traust-security/traust-sdk/go/v1/validate"
)

const (
	defaultScopeID = "local"
	bindingDomain  = "traust-binding-v1"
)

type artifactWrite struct {
	name    string
	binding Binding
	payload []byte
}

type writeState struct {
	digest    string
	lockKey   int64
	bindingID string
	binding   Binding
}

type projectFunc[T any] func(context.Context, *sql.Conn, writeState, T) error

func saveTypedArtifact[T any](
	ctx context.Context,
	store *sqlStore,
	name string,
	binding Binding,
	requirements bindingRequirements,
	artifact types.Artifact[T],
	project projectFunc[T],
) (SaveResult, error) {
	if store == nil {
		return SaveResult{}, wrap(OperationSave, PhaseInput, ErrNilDatabase)
	}
	binding = normalizedBinding(binding)
	if err := validateBinding(binding, requirements); err != nil {
		return SaveResult{}, wrap(OperationSave, PhaseInput, err)
	}
	payload := artifact.Payload()
	if err := validate.ValidateBytes(name, payload); err != nil {
		return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
	}
	var value T
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return SaveResult{}, wrap(OperationSave, PhaseDecode, err)
	}
	return store.writeArtifact(ctx, artifactWrite{name: name, binding: binding, payload: payload}, func(
		ctx context.Context,
		conn *sql.Conn,
		state writeState,
	) error {
		if project == nil {
			return nil
		}
		return project(ctx, conn, state, value)
	})
}

func (s *sqlStore) writeArtifact(
	ctx context.Context,
	input artifactWrite,
	project func(context.Context, *sql.Conn, writeState) error,
) (result SaveResult, err error) {
	digest, lockKey := identifyArtifact(input.payload)
	// Bytes go to the object store first. The key is the content digest, so a
	// retry rewrites the same object, and a binding the database commits always
	// has its bytes behind it. A failed database write can leave an object
	// with no binding; that is harmless and is cleaned up by object lifecycle
	// policy, not by this client.
	if s.objects != nil {
		if err = s.objects.PutArtifact(ctx, digest, input.payload); err != nil {
			return result, wrap(OperationSave, PhaseEvidence, err)
		}
	}
	state := writeState{
		digest:    digest,
		lockKey:   lockKey,
		bindingID: identifyBinding(digest, input.name, input.binding),
		binding:   input.binding,
	}

	conn, err := s.db.Conn(ctx)
	if err != nil {
		return result, wrap(OperationSave, PhaseConnect, err)
	}
	defer func() { _ = conn.Close() }()
	if err = s.prepareConnection(ctx, conn); err != nil {
		return result, wrap(OperationSave, PhaseConnect, err)
	}
	if err = begin(ctx, conn, s.dialect); err != nil {
		return result, wrap(OperationSave, PhaseBegin, err)
	}
	committed := false
	defer rollbackUnlessCommitted(ctx, conn, &committed)

	if err = s.lockArtifact(ctx, conn, state.lockKey); err != nil {
		return result, err
	}
	existing, found, err := s.getBinding(ctx, conn, state.bindingID)
	if err != nil {
		return result, err
	}
	if found {
		if !sameBinding(existing, input.name, state) {
			return result, wrap(OperationSave, PhaseBinding, ErrBindingMismatch)
		}
		if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
			return result, wrap(OperationSave, PhaseCommit, err)
		}
		committed = true
		return SaveResult{Digest: digest, BindingID: state.bindingID, AlreadyBound: true}, nil
	}
	if err = s.validatePredecessor(ctx, conn, input.name, state); err != nil {
		return result, err
	}
	if err = s.insertEvidence(ctx, conn, input, state); err != nil {
		return result, err
	}
	if err = s.insertBinding(ctx, conn, input.name, state); err != nil {
		return result, err
	}
	if err = project(ctx, conn, state); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return result, wrap(OperationSave, PhaseCommit, err)
	}
	committed = true
	return SaveResult{Digest: digest, BindingID: state.bindingID}, nil
}

func identifyArtifact(payload []byte) (string, int64) {
	sum := sha256.Sum256(payload)
	// #nosec G115 -- the contract requires the first eight bytes as a signed lock key.
	return hex.EncodeToString(sum[:]), int64(binary.BigEndian.Uint64(sum[:8]))
}

func identifyBinding(digest, name string, binding Binding) string {
	hash := sha256.New()
	writeDelimited := func(value string) {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	writeOptional := func(value *string) {
		if value == nil {
			_, _ = hash.Write([]byte{0})
			return
		}
		_, _ = hash.Write([]byte{1})
		writeDelimited(*value)
	}
	writeDelimited(bindingDomain)
	writeDelimited(digest)
	writeDelimited(name)
	writeDelimited(binding.ScopeID)
	writeOptional(binding.SubjectID)
	writeOptional(binding.RunID)
	writeOptional(binding.LayerID)
	return hex.EncodeToString(hash.Sum(nil))
}

func (s *sqlStore) prepareConnection(ctx context.Context, conn *sql.Conn) error {
	if s.dialect != dialectSQLite {
		return nil
	}
	_, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = ON")
	return err
}

func (s *sqlStore) lockArtifact(ctx context.Context, conn *sql.Conn, lockKey int64) error {
	if s.dialect != dialectPostgres {
		return nil
	}
	if err := s.queries.artifactLock(ctx, conn, artifactLockParams{lockKey: lockKey}); err != nil {
		return wrap(OperationSave, PhaseLock, err)
	}
	return nil
}

func (s *sqlStore) insertEvidence(
	ctx context.Context,
	conn *sql.Conn,
	input artifactWrite,
	state writeState,
) error {
	// storage/v1 records the digest and byte size only; the bytes themselves
	// live in the caller's object store (see WithObjectStore). The digest is the
	// primary key, so identical bytes always land on the same row.
	if err := s.queries.artifactEvidenceUpsert(ctx, conn, artifactEvidenceUpsertParams{
		digest:          state.digest,
		byteSize:        int64(len(input.payload)),
		firstIngestedAt: nowUTC(),
	}); err != nil {
		return wrap(OperationSave, PhaseEvidence, err)
	}
	return nil
}

func (s *sqlStore) insertBinding(
	ctx context.Context,
	conn *sql.Conn,
	name string,
	state writeState,
) error {
	if err := s.queries.artifactBindingUpsert(ctx, conn, artifactBindingUpsertParams{
		bindingId:           state.bindingID,
		artifactDigest:      state.digest,
		artifactName:        name,
		scopeId:             state.binding.ScopeID,
		subjectId:           state.binding.SubjectID,
		runId:               state.binding.RunID,
		layerId:             state.binding.LayerID,
		supersedesBindingId: state.binding.SupersedesBindingID,
		boundAt:             nowUTC(),
	}); err != nil {
		return wrap(OperationSave, PhaseBinding, err)
	}
	return nil
}

func (s *sqlStore) getBinding(
	ctx context.Context,
	conn *sql.Conn,
	bindingID string,
) (BindingRecord, bool, error) {
	var record BindingRecord
	record.BindingID = bindingID
	err := s.queries.artifactBindingGet(
		ctx,
		conn,
		artifactBindingGetParams{bindingId: bindingID},
	).Scan(
		&record.Digest,
		&record.ArtifactName,
		&record.Binding.ScopeID,
		&record.Binding.SubjectID,
		&record.Binding.RunID,
		&record.Binding.LayerID,
		&record.Binding.SupersedesBindingID,
		&record.BoundAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return BindingRecord{}, false, nil
	}
	if err != nil {
		return BindingRecord{}, false, wrap(OperationRead, PhaseBinding, err)
	}
	return record, true, nil
}

func (s *sqlStore) validatePredecessor(
	ctx context.Context,
	conn *sql.Conn,
	name string,
	state writeState,
) error {
	if state.binding.SupersedesBindingID == nil {
		return nil
	}
	if *state.binding.SupersedesBindingID == state.bindingID {
		return wrap(OperationSave, PhaseBinding, ErrBindingMismatch)
	}
	predecessor, found, err := s.getBinding(ctx, conn, *state.binding.SupersedesBindingID)
	if err != nil {
		return err
	}
	if !found {
		return wrap(OperationSave, PhaseBinding, ErrBindingNotFound)
	}
	if predecessor.ArtifactName != name ||
		predecessor.Binding.ScopeID != state.binding.ScopeID ||
		!sameOptional(predecessor.Binding.SubjectID, state.binding.SubjectID) ||
		!sameOptional(predecessor.Binding.RunID, state.binding.RunID) ||
		!sameOptional(predecessor.Binding.LayerID, state.binding.LayerID) {
		return wrap(OperationSave, PhaseBinding, ErrBindingMismatch)
	}
	return nil
}

func sameBinding(record BindingRecord, name string, state writeState) bool {
	return record.Digest == state.digest &&
		record.ArtifactName == name &&
		record.Binding.ScopeID == state.binding.ScopeID &&
		sameOptional(record.Binding.SubjectID, state.binding.SubjectID) &&
		sameOptional(record.Binding.RunID, state.binding.RunID) &&
		sameOptional(record.Binding.LayerID, state.binding.LayerID) &&
		sameOptional(record.Binding.SupersedesBindingID, state.binding.SupersedesBindingID)
}

func sameOptional(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func begin(ctx context.Context, conn *sql.Conn, dialect dialect) error {
	statement := "BEGIN IMMEDIATE"
	if dialect == dialectPostgres {
		statement = "BEGIN ISOLATION LEVEL READ COMMITTED"
	}
	_, err := conn.ExecContext(ctx, statement)
	return err
}

func rollbackUnlessCommitted(ctx context.Context, conn *sql.Conn, committed *bool) {
	if !*committed {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
	}
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
