package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/traust-security/traust-sdk/go/v1/types"
	_ "modernc.org/sqlite"
)

func openTestStorage(t *testing.T) *Client {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	client, err := NewClient(context.Background(), db, WithObjectStore(newMemoryObjects()))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return client
}

// memoryObjects is an in-memory ObjectStore for tests.
type memoryObjects struct {
	mu      sync.Mutex
	objects map[string][]byte
	putErr  error
}

func newMemoryObjects() *memoryObjects { return &memoryObjects{objects: map[string][]byte{}} }

func (m *memoryObjects) PutArtifact(_ context.Context, digest string, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.putErr != nil {
		return m.putErr
	}
	m.objects[ObjectKey("", digest)] = append([]byte(nil), payload...)
	return nil
}

func (m *memoryObjects) GetArtifact(_ context.Context, digest string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	payload, ok := m.objects[ObjectKey("", digest)]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), payload...), nil
}

func objectsOf(client *Client) *memoryObjects { return client.store.objects.(*memoryObjects) }

func sqlDB(client *Client) *sql.DB { return client.store.db }

func stringPointer(value string) *string { return &value }

func runBinding(scope string, layer *string) Binding {
	return Binding{
		ScopeID:   scope,
		SubjectID: stringPointer("sci:inventory-item:42"),
		RunID:     stringPointer("sci:scan-result:7"),
		LayerID:   layer,
	}
}

func bindingFor(name string) Binding {
	switch name {
	case "adapter-result",
		"cloud-config-audit",
		"cloud-config-findings-current",
		"compliance-assessment",
		"doc-variance",
		"operator-priv-profile",
		"pqc-blockers",
		"pqc-facts",
		"pqc-readiness",
		"refuted-register",
		"remediation",
		"report",
		"threat-model",
		"triage",
		"validation",
		"verification",
		"vuln-findings":
		return runBinding("local", nil)
	case "layer":
		return Binding{LayerID: stringPointer("ledger:layer:1")}
	default:
		return Binding{}
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	payload, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func sampleArtifacts(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	var samples map[string]json.RawMessage
	if err := json.Unmarshal(readFixture(t, "storagetest/testdata/samples.json"), &samples); err != nil {
		t.Fatal(err)
	}
	return samples
}

func mustParseArtifact[T any](
	t *testing.T,
	payload []byte,
	parse func([]byte) (types.Artifact[T], error),
) types.Artifact[T] {
	t.Helper()
	artifact, err := parse(payload)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func replaceJSONField(t *testing.T, payload []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	mutate(document)
	result, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestInitRevisionAndDependencyShape(t *testing.T) {
	ctx := context.Background()
	client := openTestStorage(t)
	if err := client.Init(ctx); err != nil {
		t.Fatal(err)
	}
	var foreignKeys int
	if err := sqlDB(client).QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		t.Fatalf("foreign keys = %d, %v", foreignKeys, err)
	}
	if _, err := sqlDB(client).ExecContext(
		ctx,
		"UPDATE traust_storage_meta SET revision = ? WHERE id = 1",
		contractRevision-1,
	); err != nil {
		t.Fatal(err)
	}
	if err := client.Init(ctx); !errors.Is(err, ErrIncompatibleRevision) {
		t.Fatalf("revision mismatch = %v", err)
	}
}

func TestBindingIDGoldenVectorAndPresence(t *testing.T) {
	digest, _ := identifyArtifact(nil)
	binding := normalizedBinding(Binding{SubjectID: stringPointer("sci:inventory-item:42")})
	got := identifyBinding(digest, "triage", binding)
	const want = "90933ec74bd66618428c4def90f4af4cb9a2ab60bc9bd24a20b64814ca2dba56"
	if got != want {
		t.Fatalf("binding ID = %s", got)
	}
	absent := identifyBinding(digest, "triage", normalizedBinding(Binding{}))
	presentEmpty := identifyBinding(
		digest,
		"triage",
		normalizedBinding(Binding{SubjectID: stringPointer("")}),
	)
	if absent == presentEmpty {
		t.Fatal("absent and present-empty identifiers collide")
	}
}

func projectionTable(name string) string {
	switch name {
	case "layer":
		// The metadata row is one of two projections; layer_event carries
		// the history and is what a lost time dimension would show up in.
		return "layer_event"
	case "triage":
		return "triage_verdict"
	case "vuln-findings":
		return "finding"
	case "corpus-registry":
		return "subject_ownership"
	// One row per THREAT, not per model, so the family and its table differ
	// by more than a dash. Was threat-register until contracts 0.24.0, when
	// threat models gained a JSON form and became the artifact themselves.
	case "threat-model":
		return "threat"
	case "operator-priv-profile":
		return "priv_profile"
	default:
		return strings.ReplaceAll(name, "-", "_")
	}
}

func TestAllArtifactsRetainEvidenceAndProject(t *testing.T) {
	ctx := context.Background()
	client := openTestStorage(t)
	samples := sampleArtifacts(t)
	for name, payload := range samples {
		result, err := client.saveNamed(ctx, name, payload, bindingFor(name))
		if err != nil {
			t.Fatalf("save %s: %v", name, err)
		}
		evidence, err := client.GetEvidence(ctx, result.Digest)
		if err != nil || !bytes.Equal(evidence, payload) {
			t.Fatalf("evidence %s: %v", name, err)
		}
	}
	for name := range samples {
		table := projectionTable(name)
		want := 1
		// Fan-out families project one row per item in their sample.
		if name == "vuln-findings" || name == "corpus-registry" ||
			name == "threat-model" {
			want = 2
		}
		// The layer sample carries three real ledger events: a confirm, a
		// regression and a resolve, so a duration is computable from it.
		if name == "layer" {
			want = 3
		}
		var got int
		if err := sqlDB(client).QueryRow("SELECT count(*) FROM " + table).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s rows = %d, want %d", table, got, want)
		}
	}
}

func TestSaveAndTypedReadExactEvidence(t *testing.T) {
	ctx := context.Background()
	client := openTestStorage(t)
	payload := readFixture(t, "storagetest/testdata/vuln-findings-populated.test.json")
	artifact, err := types.ParseVulnFindingsArtifact(payload)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{
		Binding:  runBinding("local", nil),
		Artifact: artifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(payload)
	if result.Digest != hex.EncodeToString(want[:]) || result.BindingID == "" || result.AlreadyBound {
		t.Fatalf("result = %+v", result)
	}
	stored, err := client.GetVulnFindings(ctx, result.BindingID)
	if err != nil || !bytes.Equal(stored.Payload(), payload) {
		t.Fatalf("typed read: %v", err)
	}
	record, err := client.GetBinding(ctx, result.BindingID)
	if err != nil || record.Digest != result.Digest || record.ArtifactName != "vuln-findings" {
		t.Fatalf("binding = %+v, %v", record, err)
	}
}

func TestGlobalEvidenceDedupReportsOnlyBindingNoop(t *testing.T) {
	ctx := context.Background()
	client := openTestStorage(t)
	payload := sampleArtifacts(t)["adr-registry"]
	artifact, err := types.ParseAdrRegistryArtifact(payload)
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.SaveADRRegistry(ctx, SaveADRRegistryInput{
		Binding: Binding{ScopeID: "a"}, Artifact: artifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.SaveADRRegistry(ctx, SaveADRRegistryInput{
		Binding: Binding{ScopeID: "b"}, Artifact: artifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	retry, err := client.SaveADRRegistry(ctx, SaveADRRegistryInput{
		Binding: Binding{ScopeID: "b"}, Artifact: artifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || first.BindingID == second.BindingID || !retry.AlreadyBound {
		t.Fatalf("results = %+v %+v %+v", first, second, retry)
	}
	var evidence, bindings int
	if err := sqlDB(client).QueryRow("SELECT count(*) FROM artifact_evidence").Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if err := sqlDB(client).QueryRow("SELECT count(*) FROM artifact_binding").Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if evidence != 1 || bindings != 2 {
		t.Fatalf("evidence=%d bindings=%d", evidence, bindings)
	}
}

func TestProfilesRequireRunAndLayerContext(t *testing.T) {
	ctx := context.Background()
	client := openTestStorage(t)
	samples := sampleArtifacts(t)
	findings := mustParseArtifact(t, samples["vuln-findings"], types.ParseVulnFindingsArtifact)
	if _, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{Artifact: findings}); !errors.Is(err, ErrSubjectIDRequired) {
		t.Fatalf("missing subject = %v", err)
	}
	layer := mustParseArtifact(t, samples["layer"], types.ParseLayerArtifact)
	if _, err := client.SaveLayer(ctx, SaveLayerInput{Artifact: layer}); !errors.Is(err, ErrLayerIDRequired) {
		t.Fatalf("missing layer = %v", err)
	}
	bad := runBinding("local", nil)
	bad.RunID = nil
	if _, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{Binding: bad, Artifact: findings}); !errors.Is(err, ErrRunIDRequired) {
		t.Fatalf("missing run = %v", err)
	}
}

func TestTypedReadGuardsBindingAndEvidence(t *testing.T) {
	ctx := context.Background()
	client := openTestStorage(t)
	payload := sampleArtifacts(t)["vuln-findings"]
	artifact, err := types.ParseVulnFindingsArtifact(payload)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{
		Binding: runBinding("local", nil), Artifact: artifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetTriage(ctx, result.BindingID); !errors.Is(err, ErrArtifactTypeMismatch) {
		t.Fatalf("type mismatch = %v", err)
	}
	objects := objectsOf(client)
	key := ObjectKey("", result.Digest)
	objects.objects[key] = append(objects.objects[key], ' ')
	if _, err := client.GetEvidence(ctx, result.Digest); !errors.Is(err, ErrEvidenceCorrupt) {
		t.Fatalf("corruption = %v", err)
	}
}

func TestExplicitSupersessionSelectsCurrentBinding(t *testing.T) {
	ctx := context.Background()
	client := openTestStorage(t)
	payload := sampleArtifacts(t)["vuln-findings"]
	artifact := mustParseArtifact(t, payload, types.ParseVulnFindingsArtifact)
	binding := runBinding("local", nil)
	first, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{Binding: binding, Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	corrected := replaceJSONField(t, payload, func(document map[string]any) {
		document["findings"].([]any)[0].(map[string]any)["title"] = "Explicit corrected title"
	})
	correctedArtifact, err := types.ParseVulnFindingsArtifact(corrected)
	if err != nil {
		t.Fatal(err)
	}
	binding.SupersedesBindingID = stringPointer(first.BindingID)
	second, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{
		Binding: binding, Artifact: correctedArtifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	var current string
	if err := sqlDB(client).QueryRow(
		"SELECT binding_id FROM current_binding WHERE artifact_name='vuln-findings'",
	).Scan(&current); err != nil || current != second.BindingID {
		t.Fatalf("current = %s, %v", current, err)
	}
	crossScope := binding
	crossScope.ScopeID = "other"
	if _, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{
		Binding: crossScope, Artifact: correctedArtifact,
	}); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("cross-scope supersession = %v", err)
	}
}

func TestFindingsSummaryJoinsSameRunAndOwnershipDisplay(t *testing.T) {
	ctx := context.Background()
	client := openTestStorage(t)
	samples := sampleArtifacts(t)
	layerID := "ledger:layer:1"
	binding := runBinding("local", &layerID)
	findings := mustParseArtifact(t, samples["vuln-findings"], types.ParseVulnFindingsArtifact)
	if _, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{Binding: binding, Artifact: findings}); err != nil {
		t.Fatal(err)
	}
	triagePayload := replaceJSONField(t, samples["triage"], func(document map[string]any) {
		document["findings"].([]any)[0].(map[string]any)["orig_id"] = "REPO-abcdef0-001"
	})
	triage := mustParseArtifact(t, triagePayload, types.ParseTriageArtifact)
	if _, err := client.SaveTriage(ctx, SaveTriageInput{Binding: binding, Artifact: triage}); err != nil {
		t.Fatal(err)
	}
	// Since contracts 0.37 the display repository comes from subject
	// ownership (ownership_current.repo_url), not from layer metadata.
	ownershipPayload := replaceJSONField(t, samples["corpus-registry"], func(document map[string]any) {
		document["subjects"].([]any)[0].(map[string]any)["subject_id"] = *binding.SubjectID
	})
	ownership := mustParseArtifact(t, ownershipPayload, types.ParseCorpusRegistryArtifact)
	if _, err := client.SaveCorpusRegistry(ctx, SaveCorpusRegistryInput{
		Binding: Binding{ScopeID: "local"}, Artifact: ownership,
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := client.QueryFindingsSummary(ctx, []string{"local"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Repository == nil || *rows[0].Repository != "https://example.test/repo" {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].Severity != "high" || rows[0].Verdict == nil || *rows[0].Verdict != "true_positive" {
		t.Fatalf("high row = %+v", rows[0])
	}
	other, err := client.QueryFindingsSummary(ctx, []string{"other"})
	if err != nil || len(other) != 0 {
		t.Fatalf("other scope = %+v, %v", other, err)
	}
}

func TestProjectionFailureRollsBackEvidenceAndBinding(t *testing.T) {
	ctx := context.Background()
	client := openTestStorage(t)
	payload := sampleArtifacts(t)["vuln-findings"]
	artifact, err := types.ParseVulnFindingsArtifact(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sqlDB(client).Exec(`CREATE TRIGGER fail_projection BEFORE INSERT ON finding BEGIN SELECT RAISE(ABORT, 'blocked'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{
		Binding: runBinding("local", nil), Artifact: artifact,
	}); err == nil {
		t.Fatal("expected projection failure")
	}
	for _, table := range []string{"artifact_evidence", "artifact_binding", "finding"} {
		var count int
		if err := sqlDB(client).QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s count = %d, %v", table, count, err)
		}
	}
}

func TestGeneratedProjectionFailureIsSafeAndRollsBack(t *testing.T) {
	ctx := context.Background()
	client := openTestStorage(t)
	payload := sampleArtifacts(t)["adapter-result"]
	artifact, err := types.ParseAdapterResultArtifact(payload)
	if err != nil {
		t.Fatal(err)
	}
	const privateCause = "PRIVATE_GENERATED_PROJECTION_CAUSE"
	if _, err := sqlDB(client).Exec(`CREATE TRIGGER fail_generated_projection BEFORE INSERT ON adapter_result BEGIN SELECT RAISE(ABORT, '` + privateCause + `'); END`); err != nil {
		t.Fatal(err)
	}
	_, err = client.SaveAdapterResult(ctx, SaveAdapterResultInput{
		Binding: runBinding("local", nil), Artifact: artifact,
	})
	if err == nil {
		t.Fatal("expected projection failure")
	}
	var storageErr *Error
	if !errors.As(err, &storageErr) {
		t.Fatalf("projection error type = %T", err)
	}
	if storageErr.Operation != OperationSave || storageErr.Phase != PhaseProject {
		t.Fatalf("projection error = %+v", storageErr)
	}
	if strings.Contains(err.Error(), privateCause) {
		t.Fatalf("unsafe projection error = %q", err)
	}
	for _, table := range []string{"artifact_evidence", "artifact_binding", "adapter_result"} {
		var count int
		if err := sqlDB(client).QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s count = %d, %v", table, count, err)
		}
	}
}

func TestOpaqueIdentifiersAndNULRejection(t *testing.T) {
	ctx := context.Background()
	client := openTestStorage(t)
	payload := sampleArtifacts(t)["vuln-findings"]
	artifact, err := types.ParseVulnFindingsArtifact(payload)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{
		ScopeID:   "org/scope:{one,two}",
		SubjectID: stringPointer("repo:github.com/example/project"),
		RunID:     stringPointer("scan/result/7"),
	}
	if _, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{Binding: binding, Artifact: artifact}); err != nil {
		t.Fatal(err)
	}
	binding.SubjectID = stringPointer("bad\x00id")
	if _, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{Binding: binding, Artifact: artifact}); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("NUL identifier = %v", err)
	}
}

func TestErrorStringDoesNotExposeProviderCause(t *testing.T) {
	err := wrap(OperationSave, PhaseEvidence, errors.New("PRIVATE_PAYLOAD_CONTENT"))
	if strings.Contains(err.Error(), "PRIVATE_PAYLOAD_CONTENT") {
		t.Fatalf("unsafe error = %q", err)
	}
	if !errors.Is(err, errors.Unwrap(err)) {
		t.Fatal("wrapped cause is unavailable")
	}
}
