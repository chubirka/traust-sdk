package storage

import (
	"context"
	"database/sql"
	"os"
	"testing"
)

// TestLiveCorpusReadsThroughEveryNewQuery is the smoke test for step 9: the
// three Query* methods added here, run against a store built from real
// artifacts, not fixtures. Skipped unless TRAUST_SMOKE_DB names one.
func TestLiveCorpusReadsThroughEveryNewQuery(t *testing.T) {
	path := os.Getenv("TRAUST_SMOKE_DB")
	if path == "" {
		t.Skip("set TRAUST_SMOKE_DB to a real store to run the live smoke")
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	client, err := NewClient(ctx, db, newTestObjectStore())
	if err != nil {
		t.Fatal(err)
	}
	scopes := []string{"local"}

	current, err := client.QueryValidationCurrent(ctx, scopes)
	if err != nil {
		t.Fatalf("QueryValidationCurrent: %v", err)
	}
	t.Logf("validation_current rows: %d", len(current))
	verdicts := map[string]int{}
	for _, row := range current {
		if row.Verdict != nil {
			verdicts[*row.Verdict]++
		}
	}
	t.Logf("verdicts: %v", verdicts)

	exposure, err := client.QueryValidationExposure(ctx, scopes)
	if err != nil {
		t.Fatalf("QueryValidationExposure: %v", err)
	}
	t.Logf("validation_exposure rows: %d", len(exposure))

	advisory, err := client.QueryAdvisoryExposure(ctx, scopes)
	if err != nil {
		t.Fatalf("QueryAdvisoryExposure: %v", err)
	}
	t.Logf("advisory_exposure rows: %d", len(advisory))
	if len(advisory) > 0 {
		row := advisory[0]
		t.Logf("first advisory row: advisory=%v repo=%v classification=%v evidence_level=%v",
			show(row.Advisory), show(row.Repo), show(row.Classification), show(row.EvidenceLevel))
	}
}

func show(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// TestLiveCorpusReadsThroughStepTenViews is the smoke test for the six views
// step 10 added, against a store built from real artifacts.
func TestLiveCorpusReadsThroughStepTenViews(t *testing.T) {
	path := os.Getenv("TRAUST_SMOKE_DB")
	if path == "" {
		t.Skip("set TRAUST_SMOKE_DB to a real store to run the live smoke")
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	client, err := NewClient(ctx, db, newTestObjectStore())
	if err != nil {
		t.Fatal(err)
	}
	scopes := []string{"local"}

	patterns, err := client.QueryPatternExposure(ctx, scopes)
	if err != nil {
		t.Fatalf("QueryPatternExposure: %v", err)
	}
	cwes := map[string]bool{}
	for _, row := range patterns {
		cwes[row.CWE] = true
	}
	t.Logf("pattern_exposure rows: %d across %d distinct CWEs", len(patterns), len(cwes))

	coverage, err := client.QueryAttackCoverage(ctx, scopes)
	if err != nil {
		t.Fatalf("QueryAttackCoverage: %v", err)
	}
	tiers := map[int64]int{}
	for _, row := range coverage {
		tiers[row.EvidenceTier]++
	}
	t.Logf("attack_coverage rows: %d, by evidence_tier: %v", len(coverage), tiers)

	verified, err := client.QueryVerificationCurrent(ctx, scopes)
	if err != nil {
		t.Fatalf("QueryVerificationCurrent: %v", err)
	}
	var held int64
	verdicts := map[string]int{}
	for _, row := range verified {
		held += row.Held
		if row.Verdict != nil {
			verdicts[*row.Verdict]++
		}
	}
	t.Logf("verification_current rows: %d, held: %d, verdicts: %v",
		len(verified), held, verdicts)

	regressions, err := client.QueryVerificationRegressionCurrent(ctx, scopes)
	if err != nil {
		t.Fatalf("QueryVerificationRegressionCurrent: %v", err)
	}
	t.Logf("verification_regression_current rows: %d", len(regressions))

	remediations, err := client.QueryRemediationCurrent(ctx, scopes)
	if err != nil {
		t.Fatalf("QueryRemediationCurrent: %v", err)
	}
	t.Logf("remediation_current rows: %d", len(remediations))

	posture, err := client.QueryCompliancePosture(ctx, scopes)
	if err != nil {
		t.Fatalf("QueryCompliancePosture: %v", err)
	}
	t.Logf("compliance_posture rows: %d", len(posture))
}
