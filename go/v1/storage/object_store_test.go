package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

type testObjectStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newTestObjectStore() *testObjectStore {
	return &testObjectStore{objects: make(map[string][]byte)}
}

func (s *testObjectStore) Put(_ context.Context, meta ObjectMeta, payload []byte) error {
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != meta.Digest || int64(len(payload)) != meta.Size {
		return ErrEvidenceCorrupt
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.objects[meta.Digest]; ok && !bytes.Equal(existing, payload) {
		return ErrEvidenceCorrupt
	}
	s.objects[meta.Digest] = bytes.Clone(payload)
	return nil
}

func (s *testObjectStore) Get(_ context.Context, meta ObjectMeta) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, ok := s.objects[meta.Digest]
	if !ok {
		return nil, ErrNotFound
	}
	return bytes.Clone(payload), nil
}
