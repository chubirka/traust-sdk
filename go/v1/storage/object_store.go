package storage

import (
	"context"
	"strings"
)

// ObjectMeta describes artifact bytes crossing the ObjectStore boundary.
// Digest is the storage identity; the other fields are advisory to the provider.
type ObjectMeta struct {
	Digest           string
	Size             int64
	ArtifactName     string
	ContractsVersion string
}

// ObjectStore moves exact artifact bytes by digest. Implementations belong to consumers.
// Put must accept repeated writes of the same bytes; Get wraps ErrNotFound when absent.
type ObjectStore interface {
	Put(ctx context.Context, meta ObjectMeta, payload []byte) error
	Get(ctx context.Context, meta ObjectMeta) ([]byte, error)
}

// ObjectKey returns a digest-addressed key under a caller-selected prefix.
func ObjectKey(prefix, digest string) string {
	if prefix == "" {
		return "sha256/" + digest
	}
	return strings.TrimSuffix(prefix, "/") + "/sha256/" + digest
}
