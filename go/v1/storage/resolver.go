package storage

import (
	"context"
	"strings"
)

// ObjectMeta describes the exact bytes a Resolver is asked to fetch.
// Digest and Size are what the bytes must match; the rest is advisory.
type ObjectMeta struct {
	Digest           string
	Size             int64
	ArtifactName     string
	ContractsVersion string
}

// Resolver fetches artifact bytes from a location the caller registered at Save.
//
// Storage never writes artifact bytes: the producer that wrote them (the
// harness) is the only writer, and Save records where they are. Fetch receives
// one registered reference at a time and returns the bytes found there, or an
// error wrapping ErrNotFound when it cannot resolve that reference (including a
// scheme it does not handle). Storage tries references in registration order
// and verifies size and SHA-256 itself before returning anything.
type Resolver interface {
	Fetch(ctx context.Context, reference string, meta ObjectMeta) ([]byte, error)
}

// ObjectKey returns a digest-addressed key under a caller-selected prefix, for
// producers that choose to write bytes at an immutable, self-pinning location.
func ObjectKey(prefix, digest string) string {
	if prefix == "" {
		return "sha256/" + digest
	}
	return strings.TrimSuffix(prefix, "/") + "/sha256/" + digest
}
