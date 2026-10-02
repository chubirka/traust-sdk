package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/traust-security/traust-sdk/go/v1/types"
)

func saveFindingsAt(t *testing.T, client *Client, references ...string) (SaveResult, []byte) {
	t.Helper()
	payload := sampleArtifacts(t)["vuln-findings"]
	artifact := mustParseArtifact(t, payload, types.ParseVulnFindingsArtifact)
	result, err := client.SaveVulnFindings(context.Background(), SaveVulnFindingsInput{
		Binding: runBinding("local", nil), Artifact: artifact, References: references,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result, payload
}

func TestSaveNeverReadsOrWritesBytes(t *testing.T) {
	client := openTestStorage(t)
	resolver := resolverOf(client)
	saveFindingsAt(t, client, "s3://results/a.json")
	if len(resolver.fetches) != 0 || len(resolver.objects) != 0 {
		t.Fatalf("save touched the resolver: fetches=%v objects=%d", resolver.fetches, len(resolver.objects))
	}
}

func TestReadResolvesReferencesInOrderAndVerifies(t *testing.T) {
	ctx := context.Background()
	providerErr := errors.New("provider unavailable")
	tests := []struct {
		name    string
		setup   func(r *testResolver, payload []byte)
		refs    []string
		wantErr error
	}{
		{
			name:    "missing everywhere",
			refs:    []string{"s3://gone/a.json"},
			wantErr: ErrNotFound,
		},
		{
			name: "same size wrong bytes",
			setup: func(r *testResolver, payload []byte) {
				r.Write("s3://over/a.json", bytes.Repeat([]byte("x"), len(payload)))
			},
			refs:    []string{"s3://over/a.json"},
			wantErr: ErrEvidenceCorrupt,
		},
		{
			name: "truncated",
			setup: func(r *testResolver, payload []byte) {
				r.Write("s3://short/a.json", payload[:len(payload)-1])
			},
			refs:    []string{"s3://short/a.json"},
			wantErr: ErrEvidenceCorrupt,
		},
		{
			name: "falls through to a good mirror",
			setup: func(r *testResolver, payload []byte) {
				r.Write("s3://over/a.json", bytes.Repeat([]byte("x"), len(payload)))
				r.Write("s3://mirror/a.json", payload)
			},
			refs: []string{"s3://gone/a.json", "s3://over/a.json", "s3://mirror/a.json"},
		},
		{
			name:    "provider error is preserved",
			setup:   func(r *testResolver, _ []byte) { r.err = fmt.Errorf("fetch: %w", providerErr) },
			refs:    []string{"s3://down/a.json"},
			wantErr: providerErr,
		},
		{
			name:    "no references registered",
			wantErr: ErrNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := openTestStorage(t)
			resolver := resolverOf(client)
			result, payload := saveFindingsAt(t, client, tt.refs...)
			if tt.setup != nil {
				tt.setup(resolver, payload)
			}
			got, err := client.GetPayload(ctx, result.BindingID)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("read = %v, want exact original bytes", err)
			}
			for _, meta := range resolver.metas {
				if meta.Digest != result.Digest || meta.Size != int64(len(payload)) || meta.ArtifactName != "vuln-findings" {
					t.Fatalf("fetch meta = %+v", meta)
				}
			}
		})
	}
}

func TestErrorStringDoesNotExposeResolverCause(t *testing.T) {
	client := openTestStorage(t)
	resolver := resolverOf(client)
	resolver.err = errors.New("secret-bucket-name credentials expired")
	result, _ := saveFindingsAt(t, client, "s3://secret-bucket-name/a.json")
	_, err := client.GetPayload(context.Background(), result.BindingID)
	if err == nil || bytes.Contains([]byte(err.Error()), []byte("secret-bucket-name")) {
		t.Fatalf("error string = %v", err)
	}
}

func TestReferencesValidatedBeforeAnyWrite(t *testing.T) {
	ctx := context.Background()
	for _, refs := range [][]string{{""}, {"bad\x00ref"}} {
		client := openTestStorage(t)
		payload := sampleArtifacts(t)["vuln-findings"]
		artifact := mustParseArtifact(t, payload, types.ParseVulnFindingsArtifact)
		_, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{
			Binding: runBinding("local", nil), Artifact: artifact, References: refs,
		})
		if !errors.Is(err, ErrInvalidReference) {
			t.Fatalf("refs %q = %v", refs, err)
		}
		for _, table := range []string{"artifact_evidence", "artifact_binding", "artifact_location"} {
			var count int
			if err := sqlDB(client).QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
				t.Fatalf("%s count = %d, %v", table, count, err)
			}
		}
	}
}

func TestReferencesAttachToBindingAndAccumulate(t *testing.T) {
	ctx := context.Background()
	client := openTestStorage(t)
	payload := sampleArtifacts(t)["adr-registry"]
	artifact := mustParseArtifact(t, payload, types.ParseAdrRegistryArtifact)
	a, err := client.SaveADRRegistry(ctx, SaveADRRegistryInput{
		Binding: Binding{ScopeID: "a"}, Artifact: artifact, References: []string{"file:///a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := client.SaveADRRegistry(ctx, SaveADRRegistryInput{Binding: Binding{ScopeID: "b"}, Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	retry, err := client.SaveADRRegistry(ctx, SaveADRRegistryInput{
		Binding: Binding{ScopeID: "a"}, Artifact: artifact, References: []string{"file:///a", "file:///mirror", "file:///a"},
	})
	if err != nil || !retry.AlreadyBound {
		t.Fatalf("retry = %+v, %v", retry, err)
	}
	recordA, err := client.GetBinding(ctx, a.BindingID)
	if err != nil {
		t.Fatal(err)
	}
	recordB, err := client.GetBinding(ctx, b.BindingID)
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest != b.Digest || len(recordA.References) != 2 || len(recordB.References) != 0 {
		t.Fatalf("a refs = %v, b refs = %v", recordA.References, recordB.References)
	}
}

func TestReportRolesSeparateBaselineFromCumulative(t *testing.T) {
	ctx := context.Background()
	client := openTestStorage(t)
	payload := sampleArtifacts(t)["report"]
	artifact := mustParseArtifact(t, payload, types.ParseReportArtifact)
	withRole := func(role string) Binding {
		binding := runBinding("local", nil)
		binding.Role = stringPointer(role)
		return binding
	}
	baseline, err := client.SaveReport(ctx, SaveReportInput{Binding: withRole("baseline"), Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	cumulative, err := client.SaveReport(ctx, SaveReportInput{Binding: withRole("cumulative"), Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Digest != cumulative.Digest || baseline.BindingID == cumulative.BindingID {
		t.Fatalf("baseline = %+v, cumulative = %+v", baseline, cumulative)
	}
	record, err := client.GetBinding(ctx, baseline.BindingID)
	if err != nil || record.Binding.Role == nil || *record.Binding.Role != "baseline" {
		t.Fatalf("baseline record = %+v, %v", record, err)
	}
	if _, err := client.SaveReport(ctx, SaveReportInput{Binding: withRole("latest"), Artifact: artifact}); !errors.Is(err, ErrRoleNotAllowed) {
		t.Fatalf("undeclared role = %v", err)
	}
	findings := mustParseArtifact(t, sampleArtifacts(t)["vuln-findings"], types.ParseVulnFindingsArtifact)
	if _, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{Binding: withRole("baseline"), Artifact: findings}); !errors.Is(err, ErrRoleNotAllowed) {
		t.Fatalf("role on a roleless artifact = %v", err)
	}
	corrected := replaceJSONField(t, payload, func(document map[string]any) {
		roadmap := document["remediation_roadmap"].([]any)
		document["remediation_roadmap"] = append(roadmap, roadmap[0])
	})
	correctedArtifact := mustParseArtifact(t, corrected, types.ParseReportArtifact)
	switched := withRole("cumulative")
	switched.SupersedesBindingID = stringPointer(baseline.BindingID)
	if _, err := client.SaveReport(ctx, SaveReportInput{Binding: switched, Artifact: correctedArtifact}); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("supersession changing role = %v", err)
	}
}
