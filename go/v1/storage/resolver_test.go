package storage

import (
	"bytes"
	"context"
	"fmt"
	"sync"
)

// testResolver plays the producer (Write) and the Resolver the Client reads
// through (Fetch). It counts fetches so tests can prove Save never reads bytes.
type testResolver struct {
	mu      sync.Mutex
	objects map[string][]byte
	fetches []string
	metas   []ObjectMeta
	err     error
}

func newTestResolver() *testResolver {
	return &testResolver{objects: make(map[string][]byte)}
}

func (r *testResolver) Write(reference string, payload []byte) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.objects[reference] = bytes.Clone(payload)
	return reference
}

func (r *testResolver) Fetch(_ context.Context, reference string, meta ObjectMeta) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fetches = append(r.fetches, reference)
	r.metas = append(r.metas, meta)
	if r.err != nil {
		return nil, r.err
	}
	payload, ok := r.objects[reference]
	if !ok {
		return nil, fmt.Errorf("test resolver %q: %w", reference, ErrNotFound)
	}
	return bytes.Clone(payload), nil
}

func resolverOf(client *Client) *testResolver { return client.store.resolver.(*testResolver) }
