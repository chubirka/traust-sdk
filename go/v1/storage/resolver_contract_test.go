package storage_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/traust-security/traust-sdk/go/v1/storage"
	"github.com/traust-security/traust-sdk/go/v1/storage/storagetest"
	"github.com/traust-security/traust-sdk/go/v1/types"
	_ "modernc.org/sqlite"
)

func openConsumerClient(t *testing.T, opts ...storage.Option) *storage.Client {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	client, err := storage.NewClient(ctx, db, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Init(ctx); err != nil {
		t.Fatal(err)
	}
	return client
}

func layerSample(t *testing.T) ([]byte, types.Artifact[types.Layer]) {
	t.Helper()
	samples, err := os.ReadFile("storagetest/testdata/samples.json")
	if err != nil {
		t.Fatal(err)
	}
	var documents map[string]json.RawMessage
	if err := json.Unmarshal(samples, &documents); err != nil {
		t.Fatal(err)
	}
	payload := []byte(documents["layer"])
	artifact, err := types.ParseLayerArtifact(payload)
	if err != nil {
		t.Fatal(err)
	}
	return payload, artifact
}

// The producer writes the bytes once; the consumer registers where and reads
// them back through its own resolver. Storage never holds a copy.
func TestConsumerRegistersProducerLocationAndReadsBack(t *testing.T) {
	ctx := context.Background()
	producer := &storagetest.MemoryResolver{}
	client := openConsumerClient(t, storage.WithResolver(producer))
	payload, artifact := layerSample(t)
	reference := producer.Write("git+analysis-results@abc123:findings/x/layer.json", payload)
	layerID := "test-layer"
	result, err := client.SaveLayer(ctx, storage.SaveLayerInput{
		Binding:    storage.Binding{LayerID: &layerID},
		Artifact:   artifact,
		References: []string{reference},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.GetLayer(ctx, result.BindingID)
	if err != nil || !bytes.Equal(got.Payload(), payload) {
		t.Fatalf("typed read = %v", err)
	}
	producer.Write(reference, bytes.Repeat([]byte("x"), len(payload)))
	if _, err := client.GetLayer(ctx, result.BindingID); !errors.Is(err, storage.ErrEvidenceCorrupt) {
		t.Fatalf("overwritten location = %v", err)
	}
	producer.Delete(reference)
	if _, err := client.GetLayer(ctx, result.BindingID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("deleted location = %v", err)
	}
	if storage.ObjectKey("", result.Digest) != "sha256/"+result.Digest || storage.ObjectKey("archive/", result.Digest) != "archive/sha256/"+result.Digest {
		t.Fatal("digest-addressed key differs")
	}
}

// A loader that only registers needs no resolver; reads then say so.
func TestRegisterOnlyClientNeedsNoResolver(t *testing.T) {
	ctx := context.Background()
	var typedNil *storagetest.MemoryResolver
	for name, client := range map[string]*storage.Client{
		"none":      openConsumerClient(t),
		"typed nil": openConsumerClient(t, storage.WithResolver(typedNil)),
	} {
		payload, artifact := layerSample(t)
		layerID := "test-layer"
		result, err := client.SaveLayer(ctx, storage.SaveLayerInput{
			Binding:    storage.Binding{LayerID: &layerID},
			Artifact:   artifact,
			References: []string{"s3://bucket/layer.json"},
		})
		if err != nil {
			t.Fatalf("%s: save = %v", name, err)
		}
		record, err := client.GetBinding(ctx, result.BindingID)
		if err != nil || record.ByteSize != int64(len(payload)) || len(record.References) != 1 {
			t.Fatalf("%s: binding = %+v, %v", name, record, err)
		}
		if _, err := client.GetLayer(ctx, result.BindingID); !errors.Is(err, storage.ErrNoResolver) {
			t.Fatalf("%s: read without resolver = %v", name, err)
		}
	}
}
