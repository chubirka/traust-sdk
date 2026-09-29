package storage

import (
	"context"
	"errors"
)

// ObjectStore keeps artifact bytes, addressed by their sha256 digest.
//
// storage/v1 records only an artifact's digest and byte size; the bytes live
// in the caller's object store. Implementations must treat a digest as an
// immutable key: writing the same digest twice writes the same bytes.
// GetArtifact returns an error wrapping ErrNotFound when no object exists.
type ObjectStore interface {
	PutArtifact(ctx context.Context, digest string, payload []byte) error
	GetArtifact(ctx context.Context, digest string) ([]byte, error)
}

// ErrNoObjectStore is returned by reads when the Client has no ObjectStore.
var ErrNoObjectStore = errors.New("no object store configured")

// ObjectKey is the object key for an artifact digest: "<prefix>sha256/<digest>".
// Every ObjectStore implementation in this SDK uses it, so objects written by
// one language's SDK are readable by another's.
func ObjectKey(prefix, digest string) string {
	return prefix + "sha256/" + digest
}
