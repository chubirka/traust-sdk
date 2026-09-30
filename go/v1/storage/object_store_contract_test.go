package storage_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/traust-security/traust-sdk/go/v1/storage"
	"github.com/traust-security/traust-sdk/go/v1/storage/storagetest"
	"github.com/traust-security/traust-sdk/go/v1/types"
	_ "modernc.org/sqlite"
)

func TestObjectStoreConstructionAndReadback(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := storage.NewClient(ctx, db, nil); !errors.Is(err, storage.ErrNilObjectStore) {
		t.Fatalf("nil object store = %v", err)
	}
	var typedNil *storagetest.MemoryStore
	if _, err := storage.NewClient(ctx, db, typedNil); !errors.Is(err, storage.ErrNilObjectStore) {
		t.Fatalf("typed nil object store = %v", err)
	}
	objects := &storagetest.MemoryStore{}
	client, err := storage.NewClient(ctx, db, objects)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Init(ctx); err != nil {
		t.Fatal(err)
	}
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
	layerID := "test-layer"
	input := storage.SaveLayerInput{Binding: storage.Binding{LayerID: &layerID}, Artifact: artifact}
	result, err := client.SaveLayer(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.GetLayer(ctx, result.BindingID)
	if err != nil || !bytes.Equal(got.Payload(), payload) {
		t.Fatalf("typed read = %v", err)
	}
	if storage.ObjectKey("", result.Digest) != "sha256/"+result.Digest || storage.ObjectKey("archive/", result.Digest) != "archive/sha256/"+result.Digest {
		t.Fatal("digest-addressed key differs")
	}
	if _, err := objects.Get(ctx, storage.ObjectMeta{Digest: "missing"}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing object = %v", err)
	}
	if err := objects.Corrupt(result.Digest, bytes.Repeat([]byte("x"), len(payload))); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetLayer(ctx, result.BindingID); !errors.Is(err, storage.ErrEvidenceCorrupt) {
		t.Fatalf("corrupt object = %v", err)
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != result.Digest {
		t.Fatal("unexpected digest")
	}
}
