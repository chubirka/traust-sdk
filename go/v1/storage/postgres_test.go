package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/traust-security/traust-sdk/go/v1/types"
)

const (
	postgresPreflightTimeout = 5 * time.Second
	postgresDSN              = "postgresql://traust:traust-test-only@127.0.0.1:5432/traust_test"
	postgresSetup            = "Run:\n  podman run --name traust-postgres --rm -d " +
		"-e POSTGRES_USER=traust -e POSTGRES_PASSWORD=traust-test-only " +
		"-e POSTGRES_DB=traust_test -p 127.0.0.1:5432:5432 " +
		"-v traust-postgres-data:/var/lib/postgresql/data docker.io/library/postgres:16"
)

func openPostgresStorage(t *testing.T) (*Client, *sql.DB) {
	t.Helper()
	admin, err := sql.Open("pgx", postgresDSN)
	if err != nil {
		t.Skipf("PostgreSQL integration skipped: %v. %s", err, postgresSetup)
	}
	preflightCtx, cancel := context.WithTimeout(context.Background(), postgresPreflightTimeout)
	err = admin.PingContext(preflightCtx)
	cancel()
	if err != nil {
		_ = admin.Close()
		t.Skipf("PostgreSQL integration skipped: %v. %s", err, postgresSetup)
	}
	schema := fmt.Sprintf("go_storage_test_%d", time.Now().UnixNano())
	if _, err = admin.Exec("DROP SCHEMA IF EXISTS traust_storage CASCADE"); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	if _, err = admin.Exec("CREATE SCHEMA " + schema); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP SCHEMA IF EXISTS traust_storage CASCADE")
		_, _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE")
		_ = admin.Close()
	})

	dsn := postgresDSN + "?options=" + url.QueryEscape("-csearch_path="+schema+",traust_storage")
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	client, err := NewClient(context.Background(), db, WithObjectStore(newMemoryObjects()))
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return client, db
}

func TestPostgresBindingProtocol(t *testing.T) {
	ctx := context.Background()
	client, db := openPostgresStorage(t)
	payload, err := os.ReadFile("storagetest/testdata/vuln-findings-populated.test.json")
	if err != nil {
		t.Fatal(err)
	}
	payload = append(bytes.TrimSpace(payload), []byte(" \n")...)
	artifact, err := types.ParseVulnFindingsArtifact(payload)
	if err != nil {
		t.Fatal(err)
	}
	binding := runBinding("go-storage-test", stringPointer("ledger:layer:1"))
	result, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{
		Binding: binding, Artifact: artifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := client.GetVulnFindings(ctx, result.BindingID)
	if err != nil || !bytes.Equal(stored.Payload(), payload) {
		t.Fatalf("exact read: %v", err)
	}
	again, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{
		Binding: binding, Artifact: artifact,
	})
	if err != nil || !again.AlreadyBound {
		t.Fatalf("duplicate = %+v, %v", again, err)
	}
	other, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{
		Binding: runBinding("other-scope", stringPointer("ledger:layer:1")), Artifact: artifact,
	})
	if err != nil || other.AlreadyBound || other.BindingID == result.BindingID {
		t.Fatalf("other binding = %+v, %v", other, err)
	}
	var evidence, bindings int
	if err = db.QueryRow("SELECT count(*) FROM artifact_evidence").Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("SELECT count(*) FROM artifact_binding").Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if evidence != 1 || bindings != 2 {
		t.Fatalf("evidence=%d bindings=%d", evidence, bindings)
	}
}

func TestPostgresStorageDoesNotCollideWithApplicationTables(t *testing.T) {
	ctx := context.Background()
	client, db := openPostgresStorage(t)
	if _, err := db.Exec("CREATE TABLE report (marker TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO report VALUES ('application-owned')"); err != nil {
		t.Fatal(err)
	}
	var samples map[string]json.RawMessage
	if err := json.Unmarshal(readFixture(t, "storagetest/testdata/samples.json"), &samples); err != nil {
		t.Fatal(err)
	}
	report := mustParseArtifact(t, samples["report"], types.ParseReportArtifact)
	if _, err := client.SaveReport(ctx, SaveReportInput{
		Binding: runBinding("go-storage-test", nil), Artifact: report,
	}); err != nil {
		t.Fatal(err)
	}
	var marker string
	if err := db.QueryRow("SELECT marker FROM report").Scan(&marker); err != nil {
		t.Fatal(err)
	}
	if marker != "application-owned" {
		t.Fatalf("application report marker = %q", marker)
	}
	var stored int
	if err := db.QueryRow("SELECT count(*) FROM traust_storage.report").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 1 {
		t.Fatalf("storage reports = %d", stored)
	}
}

func TestPostgresFindingsSummaryUsesSameRunAndJSONScope(t *testing.T) {
	ctx := context.Background()
	client, _ := openPostgresStorage(t)
	var samples map[string]json.RawMessage
	if err := json.Unmarshal(
		readFixture(t, "storagetest/testdata/samples.json"),
		&samples,
	); err != nil {
		t.Fatal(err)
	}
	layerID := "ledger:layer:1"
	binding := runBinding("go-storage-test", &layerID)
	findings := mustParseArtifact(t, samples["vuln-findings"], types.ParseVulnFindingsArtifact)
	if _, err := client.SaveVulnFindings(ctx, SaveVulnFindingsInput{
		Binding: binding, Artifact: findings,
	}); err != nil {
		t.Fatal(err)
	}
	triagePayload := replaceJSONField(t, samples["triage"], func(document map[string]any) {
		document["findings"].([]any)[0].(map[string]any)["orig_id"] = "REPO-abcdef0-001"
	})
	triage := mustParseArtifact(t, triagePayload, types.ParseTriageArtifact)
	if _, err := client.SaveTriage(ctx, SaveTriageInput{Binding: binding, Artifact: triage}); err != nil {
		t.Fatal(err)
	}
	layer := mustParseArtifact(t, samples["layer"], types.ParseLayerArtifact)
	if _, err := client.SaveLayer(ctx, SaveLayerInput{
		Binding: Binding{ScopeID: "go-storage-test", LayerID: &layerID}, Artifact: layer,
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := client.QueryFindingsSummary(ctx, []string{"go-storage-test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Repository == nil || *rows[0].Repository != "https://example.test/repo" {
		t.Fatalf("rows = %+v", rows)
	}
	other, err := client.QueryFindingsSummary(ctx, []string{"other"})
	if err != nil || len(other) != 0 {
		t.Fatalf("other scope = %+v, %v", other, err)
	}
}
