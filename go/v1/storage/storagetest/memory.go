package storagetest

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/traust-security/traust-sdk/go/v1/storage"
)

// MemoryResolver is an in-memory artifact location for consumers and SDK tests.
// Write plays the producer that owns the bytes; Fetch is the storage.Resolver
// the Client reads through. It returns whatever is at a reference, so tests can
// overwrite a location to exercise the SDK's own digest and size checks.
type MemoryResolver struct {
	mu      sync.Mutex
	objects map[string][]byte
}

var _ storage.Resolver = (*MemoryResolver)(nil)

// Write stores exact bytes at reference, replacing anything already there, and
// returns the reference so it can be passed straight to a Save input.
func (r *MemoryResolver) Write(reference string, payload []byte) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.objects == nil {
		r.objects = make(map[string][]byte)
	}
	r.objects[reference] = bytes.Clone(payload)
	return reference
}

// Delete removes the bytes at reference.
func (r *MemoryResolver) Delete(reference string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.objects, reference)
}

// Fetch returns the bytes at reference, or an error wrapping storage.ErrNotFound.
func (r *MemoryResolver) Fetch(_ context.Context, reference string, _ storage.ObjectMeta) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	payload, ok := r.objects[reference]
	if !ok {
		return nil, fmt.Errorf("memory resolver %q: %w", reference, storage.ErrNotFound)
	}
	return bytes.Clone(payload), nil
}
