package storagetest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"github.com/traust-security/traust-sdk/go/v1/storage"
)

// MemoryStore is an in-memory ObjectStore for consumers and SDK tests.
type MemoryStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

// Put retains exact bytes by digest and rejects conflicting or invalid content.
func (s *MemoryStore) Put(_ context.Context, meta storage.ObjectMeta, payload []byte) error {
	if s == nil {
		return storage.ErrNilObjectStore
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != meta.Digest || int64(len(payload)) != meta.Size {
		return storage.ErrEvidenceCorrupt
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.objects == nil {
		s.objects = make(map[string][]byte)
	}
	if previous, ok := s.objects[meta.Digest]; ok && !bytes.Equal(previous, payload) {
		return storage.ErrEvidenceCorrupt
	}
	s.objects[meta.Digest] = bytes.Clone(payload)
	return nil
}

// Get returns a copy of the bytes for a digest or ErrNotFound when absent.
func (s *MemoryStore) Get(_ context.Context, meta storage.ObjectMeta) ([]byte, error) {
	if s == nil {
		return nil, storage.ErrNilObjectStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, ok := s.objects[meta.Digest]
	if !ok {
		return nil, storage.ErrNotFound
	}
	if meta.Size != 0 && int64(len(payload)) != meta.Size {
		return nil, storage.ErrEvidenceCorrupt
	}
	return bytes.Clone(payload), nil
}

// Corrupt substitutes test bytes to exercise SDK integrity checks.
func (s *MemoryStore) Corrupt(digest string, payload []byte) error {
	if s == nil {
		return storage.ErrNilObjectStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.objects[digest]; !ok {
		return storage.ErrNotFound
	}
	s.objects[digest] = bytes.Clone(payload)
	return nil
}
