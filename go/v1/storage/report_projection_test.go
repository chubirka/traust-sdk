package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/traust-security/traust-sdk/go/v1/types"
)

func populatedReport(t *testing.T) []byte {
	t.Helper()
	return replaceJSONField(t, sampleArtifacts(t)["report"], func(document map[string]any) {
		document["findings"] = []any{
			map[string]any{
				"id": "FIND-001", "title": "Disposed finding", "severity": "high",
				"description": strings.Repeat("Synthetic evidence. ", 4), "remediation": strings.Repeat("Apply a correction. ", 2),
				"fingerprint": strings.Repeat("a", 64), "fingerprint_algo": "v1",
				"validation_status": "confirmed", "category": "injection", "cwes": []any{"CWE-79"},
				"locations":       []any{map[string]any{"path": "test.go", "lines": "1-2"}},
				"asvs_references": []any{"V5.3.8"}, "peach_references": []any{"PEACH-P"}, "capec": []any{"CAPEC-63"},
				"attack_pattern": "Synthetic pattern", "cvss": map[string]any{"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
				"evidence":           []any{map[string]any{"code": "synthetic", "language": "text"}},
				"effective_severity": "critical", "origin": "vuln-scan", "source_findings": []any{"source:FIND-001"},
				"passes": []any{1, 2}, "remediation_effort": "moderate", "pqc_classification": "pqc-adoption",
				"isolation_boundary": "test-boundary", "isolation_dimensions": []any{"privilege"},
				"dependency": map[string]any{"advisory": "TEST-001", "module": "test-module"},
				"disposition": map[string]any{
					"validity": "confirmed", "resolution": "fix_in_progress", "assurance": "execution_proven",
					"last_updated": "2026-01-02T00:00:00Z", "events": []any{},
					"conflict": false, "fp_overridden": true, "fp_reassertion_blocked": true, "refuted_awaiting_signoff": false,
					"severity_override": map[string]any{"severity": "critical", "by": "reviewer@example.test", "at": "2026-01-02T00:00:00Z"},
				},
			},
			map[string]any{
				"id": "FIND-002", "title": "Bare finding", "severity": "low",
				"description": strings.Repeat("Synthetic baseline. ", 4), "remediation": strings.Repeat("Review the baseline. ", 2),
				"fingerprint": strings.Repeat("a", 64), "cwes": []any{"CWE-200"}, "locations": []any{map[string]any{"path": "bare.go"}},
			},
		}
	})
}

func checkReportProjection(t *testing.T, client *Client, db *sql.DB, prefix string) {
	t.Helper()
	ctx := context.Background()
	payload := append(populatedReport(t), []byte(" \n")...)
	artifact := mustParseArtifact(t, payload, types.ParseReportArtifact)
	input := SaveReportInput{Binding: runBinding("report-test", nil), Artifact: artifact}
	result, err := client.SaveReport(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetReport(ctx, result.BindingID); !errors.Is(err, ErrArtifactBytesNotRetained) {
		t.Fatalf("report read = %v, want ErrArtifactBytesNotRetained", err)
	}
	var original map[string]any
	if err := json.Unmarshal(payload, &original); err != nil {
		t.Fatal(err)
	}
	findings := original["findings"].([]any)
	rows, err := db.QueryContext(ctx, "SELECT * FROM "+prefix+"report_finding ORDER BY finding_id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	jsonFields := map[string]bool{
		"severity_override": true, "cwes": true, "locations": true, "asvs_references": true,
		"peach_references": true, "capec": true, "cvss": true, "evidence": true,
		"source_findings": true, "passes": true, "isolation_dimensions": true, "dependency": true,
	}
	flagFields := map[string]bool{"conflict": true, "fp_overridden": true, "fp_reassertion_blocked": true, "refuted_awaiting_signoff": true}
	count := 0
	for rows.Next() {
		if count >= len(findings) {
			t.Fatal("unexpected extra finding")
		}
		finding := findings[count].(map[string]any)
		disposition, _ := finding["disposition"].(map[string]any)
		values := make([]any, len(columns))
		targets := make([]any, len(columns))
		for index := range values {
			targets[index] = &values[index]
		}
		if err := rows.Scan(targets...); err != nil {
			t.Fatal(err)
		}
		for index, column := range columns {
			want := finding[column]
			if value, exists := disposition[column]; exists {
				want = value
			}
			switch column {
			case "binding_id":
				want = result.BindingID
			case "artifact_digest":
				want = result.Digest
			case "finding_id":
				want = finding["id"]
			}
			got := values[index]
			if data, ok := got.([]byte); ok {
				got = string(data)
			}
			if want == nil && got != nil {
				t.Errorf("finding %v column %s: expected SQL NULL, got %#v", finding["id"], column, got)
			}
			if jsonFields[column] && got != nil {
				if err := json.Unmarshal([]byte(got.(string)), &got); err != nil {
					t.Fatal(err)
				}
			}
			if flagFields[column] && want != nil {
				flag := int64(0)
				if want.(bool) {
					flag = 1
				}
				want = flag
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("finding %v column %s: got %#v, want %#v", finding["id"], column, got, want)
			}
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("projected %d findings, want 2", count)
	}
	again, err := client.SaveReport(ctx, input)
	if err != nil || !again.AlreadyBound || again.BindingID != result.BindingID {
		t.Fatalf("retry: %+v, %v", again, err)
	}
	var persisted int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+prefix+"report_finding").Scan(&persisted); err != nil || persisted != 2 {
		t.Fatalf("retry finding count = %d, %v", persisted, err)
	}
}

func TestReportFindingProjection(t *testing.T) {
	client := openTestStorage(t)
	checkReportProjection(t, client, sqlDB(client), "")
}

func TestPostgresReportFindingProjection(t *testing.T) {
	client, db := openPostgresStorage(t)
	checkReportProjection(t, client, db, "traust_storage.")
}

func TestReportFindingProjectionEmpty(t *testing.T) {
	client := openTestStorage(t)
	artifact := mustParseArtifact(t, sampleArtifacts(t)["report"], types.ParseReportArtifact)
	if _, err := client.SaveReport(context.Background(), SaveReportInput{Binding: runBinding("empty", nil), Artifact: artifact}); err != nil {
		t.Fatal(err)
	}
	var roots, children int
	if err := sqlDB(client).QueryRow("SELECT count(*) FROM report").Scan(&roots); err != nil {
		t.Fatal(err)
	}
	if err := sqlDB(client).QueryRow("SELECT count(*) FROM report_finding").Scan(&children); err != nil {
		t.Fatal(err)
	}
	if roots != 1 || children != 0 {
		t.Fatalf("empty report: roots=%d children=%d", roots, children)
	}
}

func TestReportFindingProjectionRollback(t *testing.T) {
	client := openTestStorage(t)
	db := sqlDB(client)
	if _, err := db.Exec("CREATE TRIGGER reject_second_finding BEFORE INSERT ON report_finding WHEN NEW.finding_id = 'FIND-002' BEGIN SELECT RAISE(ABORT, 'synthetic projection failure'); END"); err != nil {
		t.Fatal(err)
	}
	artifact := mustParseArtifact(t, populatedReport(t), types.ParseReportArtifact)
	input := SaveReportInput{Binding: runBinding("rollback", nil), Artifact: artifact}
	if _, err := client.SaveReport(context.Background(), input); err == nil {
		t.Fatal("expected child projection failure")
	}
	for _, table := range []string{"artifact_evidence", "artifact_binding", "report", "report_finding"} {
		var count int
		if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("rollback %s: count=%d, %v", table, count, err)
		}
	}
	if _, err := db.Exec("DROP TRIGGER reject_second_finding"); err != nil {
		t.Fatal(err)
	}
	result, err := client.SaveReport(context.Background(), input)
	if err != nil || result.AlreadyBound {
		t.Fatalf("retry after rollback: %+v, %v", result, err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM report_finding").Scan(&count); err != nil || count != 2 {
		t.Fatalf("retry after rollback findings: count=%d, %v", count, err)
	}
}
