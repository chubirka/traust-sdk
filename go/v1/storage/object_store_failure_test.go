package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/traust-security/traust-sdk/go/v1/types"
	_ "modernc.org/sqlite"
)

type failureStore struct {
	putErr   error
	getErr   error
	getData  []byte
	putMeta  ObjectMeta
	getMeta  ObjectMeta
	putCount int
}

func (s *failureStore) Put(_ context.Context, meta ObjectMeta, _ []byte) error {
	s.putMeta = meta
	s.putCount++
	return s.putErr
}

func (s *failureStore) Get(_ context.Context, meta ObjectMeta) ([]byte, error) {
	s.getMeta = meta
	return s.getData, s.getErr
}

func TestExternalPutFailureLeavesDatabaseEmpty(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	providerErr := fmt.Errorf("provider: %w", ErrNotFound)
	objects := &failureStore{putErr: providerErr}
	client, err := NewClient(ctx, db, objects)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Init(ctx); err != nil {
		t.Fatal(err)
	}
	payload := sampleArtifacts(t)["vuln-findings"]
	artifact := mustParseArtifact(t, payload, types.ParseVulnFindingsArtifact)
	_, err = client.SaveVulnFindings(ctx, SaveVulnFindingsInput{Binding: runBinding("local", nil), Artifact: artifact})
	if !errors.Is(err, providerErr) {
		t.Fatalf("put failure = %v", err)
	}
	if objects.putCount != 1 || objects.putMeta.ArtifactName != "vuln-findings" || objects.putMeta.ContractsVersion != storageFormatVersion || objects.putMeta.Size != int64(len(payload)) {
		t.Fatalf("put metadata = %+v, count = %d", objects.putMeta, objects.putCount)
	}
	for _, name := range []string{"artifact_evidence", "artifact_binding", "finding"} {
		var count int
		if err := db.QueryRow("SELECT count(*) FROM " + name).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s count = %d, err = %v", name, count, err)
		}
	}
}

func TestExternalReadErrorsPreserveIdentityAndVerifyBytes(t *testing.T) {
	ctx := context.Background()
	client := openTestStorage(t)
	payload := sampleArtifacts(t)["vuln-findings"]
	artifact := mustParseArtifact(t, payload, types.ParseVulnFindingsArtifact)
	result, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{Binding: runBinding("local", nil), Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	objects := &failureStore{getErr: fmt.Errorf("missing: %w", ErrNotFound)}
	client.store.objects = objects
	if _, err := client.GetVulnFindings(ctx, result.BindingID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing bound evidence = %v", err)
	}
	if objects.getMeta.Digest != result.Digest || objects.getMeta.Size != int64(len(payload)) || objects.getMeta.ArtifactName != "vuln-findings" {
		t.Fatalf("typed read metadata = %+v", objects.getMeta)
	}
	objects.getErr = nil
	objects.getData = bytes.Repeat([]byte("x"), len(payload))
	if _, err := client.GetVulnFindings(ctx, result.BindingID); !errors.Is(err, ErrEvidenceCorrupt) {
		t.Fatalf("same-size wrong bytes = %v", err)
	}
	objects.getData = payload[:len(payload)-1]
	if _, err := client.GetEvidence(ctx, result.Digest); !errors.Is(err, ErrEvidenceCorrupt) {
		t.Fatalf("truncated evidence = %v", err)
	}
	if objects.getMeta.ArtifactName != "" || objects.getMeta.Size != int64(len(payload)) {
		t.Fatalf("raw read metadata = %+v", objects.getMeta)
	}
}
