package storage

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/traust-security/traust-sdk/go/v1/types"
)

func openStorageWithoutObjects(t *testing.T) *Client {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	client, err := NewClient(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return client
}

func saveSampleFindings(t *testing.T, client *Client) (SaveResult, error) {
	t.Helper()
	artifact, err := types.ParseVulnFindingsArtifact(sampleArtifacts(t)["vuln-findings"])
	if err != nil {
		t.Fatal(err)
	}
	return client.SaveVulnFindings(context.Background(), SaveVulnFindingsInput{
		Binding: runBinding("local", nil), Artifact: artifact,
	})
}

func TestObjectKeyIsContentAddressed(t *testing.T) {
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if got := ObjectKey("prod/", digest); got != "prod/sha256/"+digest {
		t.Fatalf("ObjectKey = %q", got)
	}
}

func TestSaveWritesBytesUnderTheirDigest(t *testing.T) {
	client := openTestStorage(t)
	result, err := saveSampleFindings(t, client)
	if err != nil {
		t.Fatal(err)
	}
	stored, ok := objectsOf(client).objects[ObjectKey("", result.Digest)]
	if !ok {
		t.Fatal("saved bytes are not in the object store")
	}
	if digest, _ := identifyArtifact(stored); digest != result.Digest {
		t.Fatalf("stored digest %s != bound digest %s", digest, result.Digest)
	}
	var size int64
	if err := sqlDB(client).QueryRow(
		"SELECT byte_size FROM artifact_evidence WHERE digest = ?", result.Digest,
	).Scan(&size); err != nil || size != int64(len(stored)) {
		t.Fatalf("byte_size = %d (%v), want %d", size, err, len(stored))
	}
}

func TestObjectStoreFailureStopsTheSave(t *testing.T) {
	client := openTestStorage(t)
	objectsOf(client).putErr = errors.New("bucket unavailable")
	if _, err := saveSampleFindings(t, client); err == nil {
		t.Fatal("save succeeded although the bytes could not be stored")
	}
	var bindings int
	if err := sqlDB(client).QueryRow("SELECT count(*) FROM artifact_binding").Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if bindings != 0 {
		t.Fatalf("%d binding(s) recorded without bytes", bindings)
	}
}

func TestReadsWithoutAnObjectStoreSayWhy(t *testing.T) {
	client := openStorageWithoutObjects(t)
	result, err := saveSampleFindings(t, client)
	if err != nil {
		t.Fatalf("save without an object store should still record the binding: %v", err)
	}
	if _, err := client.GetEvidence(context.Background(), result.Digest); !errors.Is(err, ErrNoObjectStore) {
		t.Fatalf("GetEvidence = %v, want ErrNoObjectStore", err)
	}
	if _, err := client.GetVulnFindings(context.Background(), result.BindingID); !errors.Is(err, ErrNoObjectStore) {
		t.Fatalf("GetVulnFindings = %v, want ErrNoObjectStore", err)
	}
}

func TestMissingObjectIsNotFound(t *testing.T) {
	client := openTestStorage(t)
	result, err := saveSampleFindings(t, client)
	if err != nil {
		t.Fatal(err)
	}
	delete(objectsOf(client).objects, ObjectKey("", result.Digest))
	if _, err := client.GetEvidence(context.Background(), result.Digest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetEvidence = %v, want ErrNotFound", err)
	}
}
