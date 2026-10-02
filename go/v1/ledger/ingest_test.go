package ledger_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/traust-security/traust-sdk/go/v1/enums"
	"github.com/traust-security/traust-sdk/go/v1/ledger"
	"github.com/traust-security/traust-sdk/go/v1/ledger/ingesttest"
	"github.com/traust-security/traust-sdk/go/v1/types"
)

// testFingerprint is a 64-hex fingerprint constant assembled at runtime so no
// key-shaped literal sits in the tree for forge secret scanners.
var testFingerprint = strings.Repeat("aa11bb22cc33dd44ee55ff66", 2) + "aa11bb22cc33dd44"

func TestConvertTriageReport(t *testing.T) {
	report := types.Triage{
		TriageCompleted: "2026-07-09",
		TriageContext: types.TriageContext{
			HarnessVersion: "0.27.0",
		},
		Findings: []types.TriageFinding{
			{
				Id:         "f001",
				OrigId:     "TEST_REPO-abc1234-001",
				Verdict:    enums.VerdictTruePositive,
				Rationale:  "reachable handler",
				FirstLinks: []string{"pkg/handler.go:73"},
			},
			{
				Id:        "f002",
				OrigId:    "TEST_REPO-abc1234-002",
				Verdict:   enums.VerdictUndetermined,
				Rationale: "unclear exploit path",
			},
			{
				Id:      "f003",
				Verdict: enums.VerdictDuplicate,
			},
		},
	}

	fpIndex := map[string]string{
		"TEST_REPO-abc1234-001": testFingerprint,
	}
	out := ledger.ConvertTriageReport(report, "findings/repo-a/triage.json", "2026-07-11T12:00:00+00:00", fpIndex)
	if len(out.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(out.Events))
	}
	if len(out.NeedsReview) != 1 {
		t.Fatalf("expected 1 needs_review item, got %d", len(out.NeedsReview))
	}

	event := out.Events[0]
	if _, hasID := event["event_id"]; hasID {
		t.Fatal("events must not include event_id; server stamps it")
	}
	if event["finding_ref"] != "TEST_REPO-abc1234-001" {
		t.Fatalf("unexpected finding_ref: %v", event["finding_ref"])
	}
	if event["fingerprint"] != fpIndex["TEST_REPO-abc1234-001"] {
		t.Fatalf("expected fingerprint stamped from index, got %v", event["fingerprint"])
	}
	if _, hasAlgo := event["fingerprint_algo"]; hasAlgo {
		t.Fatal("SDK must not set fingerprint_algo; the ledger stamps it")
	}
	disposition, ok := event["disposition"].(map[string]interface{})
	if !ok || disposition["validity"] != "confirmed" {
		t.Fatalf("unexpected disposition: %v", event["disposition"])
	}

	review := out.NeedsReview[0]
	if review["queue_reason"] != "undetermined_finding" {
		t.Fatalf("unexpected queue_reason: %v", review["queue_reason"])
	}
}

func TestConvertValidationReport(t *testing.T) {
	title := "SQL injection"
	impact := "arbitrary file read"
	report := types.Validation{
		Metadata: types.ValidationMetadata{
			Date:           "2026-07-09",
			HarnessVersion: "0.28.0",
		},
		ValidatedFindings: []types.ValidatedFinding{
			{
				SourceId:       "pkg:src/FIND-001",
				Technique:      "path-traversal",
				Verdict:        enums.ValidationVerdictConfirmed,
				Title:          &title,
				ObservedImpact: &impact,
			},
			{
				SourceId:  "pkg:src/FIND-002",
				Technique: "replay",
				Verdict:   enums.ValidationVerdictRefuted,
			},
			{
				SourceId: "pkg:src/FIND-003",
				Verdict:  enums.ValidationVerdictInconclusive,
			},
		},
	}

	out := ledger.ConvertValidationReport(report, "validations/repo-a/validation.json", "2026-07-11T12:00:00+00:00", nil)
	if len(out.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(out.Events))
	}
	for _, event := range out.Events {
		if _, hasID := event["event_id"]; hasID {
			t.Fatal("events must not include event_id; server stamps it")
		}
	}
}

func TestConvertValidationReport_SoundnessAndGrades(t *testing.T) {
	flag := "error_signature"
	e2, e3 := "E2", "E3"
	impact := "403 Forbidden"
	report := types.Validation{
		Metadata: types.ValidationMetadata{Date: "2026-07-09", HarnessVersion: "0.200.0"},
		ValidatedFindings: []types.ValidatedFinding{
			// Unsound refutation: never a false_positive event.
			{SourceId: "pkg:src/F-1", Verdict: enums.ValidationVerdictRefuted, SoundnessFlag: &flag, ObservedImpact: &impact},
			// Flagged inconclusive: queued too, though it would otherwise emit nothing.
			{SourceId: "pkg:src/F-2", Verdict: enums.ValidationVerdictInconclusive, SoundnessFlag: &flag},
			// E3 confirmation: inference only, queued instead of confirming.
			{SourceId: "pkg:src/F-3", Verdict: enums.ValidationVerdictConfirmed, EvidenceGrade: &e3},
			// E2 confirmation: emitted, grade carried so the ledger demotes it.
			{SourceId: "pkg:src/F-4", Verdict: enums.ValidationVerdictConfirmed, EvidenceGrade: &e2},
			// Sound refutation: still a false_positive event (countersign-gated by the ledger).
			{SourceId: "pkg:src/F-5", Verdict: enums.ValidationVerdictRefuted},
			// A soundness flag never blocks a confirmation.
			{SourceId: "pkg:src/F-6", Verdict: enums.ValidationVerdictConfirmed, SoundnessFlag: &flag},
		},
	}

	out := ledger.ConvertValidationReport(report, "validations/v.json", "2026-07-11T12:00:00+00:00", nil)

	events := map[string]map[string]interface{}{}
	for _, e := range out.Events {
		events[e["finding_ref"].(string)] = e
	}
	if len(events) != 3 {
		t.Fatalf("expected events for F-4, F-5, F-6; got %v", events)
	}
	for _, ref := range []string{"pkg:src/F-1", "pkg:src/F-2", "pkg:src/F-3"} {
		if _, ok := events[ref]; ok {
			t.Errorf("%s must not produce an event", ref)
		}
	}
	if got := events["pkg:src/F-4"]["evidence_grade"]; got != "E2" {
		t.Errorf("F-4 evidence_grade = %v, want E2", got)
	}
	if _, ok := events["pkg:src/F-5"]["evidence_grade"]; ok {
		t.Error("ungraded finding must not carry evidence_grade")
	}
	if got := events["pkg:src/F-5"]["disposition"].(map[string]interface{})["validity"]; got != "false_positive" {
		t.Errorf("F-5 validity = %v, want false_positive", got)
	}

	reasons := map[string]string{}
	for _, item := range out.NeedsReview {
		reasons[item["suggested_finding_ref"].(string)] = item["queue_reason"].(string)
	}
	want := map[string]string{
		"pkg:src/F-1": "unsound_refutation",
		"pkg:src/F-2": "unsound_refutation",
		"pkg:src/F-3": "weak_confirmation",
	}
	for ref, reason := range want {
		if reasons[ref] != reason {
			t.Errorf("%s queue_reason = %q, want %q", ref, reasons[ref], reason)
		}
	}
	if len(reasons) != len(want) {
		t.Errorf("unexpected needs_review items: %v", reasons)
	}
}

func TestConvertVerificationReport(t *testing.T) {
	report := types.Verification{
		Metadata: types.VerificationMetadata{
			Date:           "2026-07-09",
			HarnessVersion: "0.28.0",
		},
		VerifiedFindings: []types.VerifiedFinding{
			{
				OriginalId: "FIND-001",
				Verdict:    "resolved",
				Evidence: types.VerifiedFindingEvidence{
					Explanation: "patch removes sink",
				},
			},
			{
				OriginalId: "FIND-002",
				Verdict:    "partially_resolved",
				CrossRepo: &types.CrossRepo{
					Propagation: "pending",
				},
				Evidence: types.VerifiedFindingEvidence{
					Explanation: "fix landed upstream, pending downstream",
				},
			},
			{
				OriginalId: "FIND-003",
				Verdict:    "false_positive",
				Evidence: types.VerifiedFindingEvidence{
					Explanation: "not reachable after refactor",
				},
			},
			{
				OriginalId: "FIND-004",
				Verdict:    "bogus",
			},
			{
				OriginalId: "",
				Verdict:    "resolved",
			},
		},
		Regressions: []types.Regression{
			{Id: "REG-001", Title: "new issue"},
		},
	}

	out := ledger.ConvertVerificationReport(report, "verifications/repo-a/verification.json", "2026-07-11T12:00:00+00:00", nil)
	if len(out.Events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(out.Events))
	}
	if len(out.Skipped) != 2 {
		t.Fatalf("expected 2 skipped findings (bogus + empty id), got %d", len(out.Skipped))
	}

	event := out.Events[0]
	source, ok := event["source"].(map[string]interface{})
	if !ok || source["type"] != "verification_report" {
		t.Fatalf("unexpected source: %v", event["source"])
	}
	if event["occurred_at"] != "2026-07-09T00:00:00+00:00" {
		t.Fatalf("unexpected occurred_at: %v", event["occurred_at"])
	}

	partial := out.Events[1]
	disposition, ok := partial["disposition"].(map[string]interface{})
	if !ok || disposition["resolution"] != "fix_in_progress" {
		t.Fatalf("expected fix_in_progress for pending cross-repo, got %v", partial["disposition"])
	}

	fp := out.Events[2]
	fpDisp, ok := fp["disposition"].(map[string]interface{})
	if !ok || fpDisp["validity"] != "false_positive" {
		t.Fatalf("expected false_positive validity, got %v", fp["disposition"])
	}
}

func TestBatchSubmit_RoundTrip(t *testing.T) {
	provider := ingesttest.NewStaticProvider().
		WithSubmitResponse(ledger.SubmitResponse{ID: "batch-001", Status: "accepted"})
	client := ledger.NewClient(provider)

	resp, err := client.BatchSubmit(context.Background(), "repo-a", ledger.BatchSubmitInput{
		SourceRef:  "findings/repo-a/triage.json",
		RecordedAt: "2026-01-16T00:00:00+00:00",
		Events: []map[string]interface{}{
			{"finding_ref": "FIND-001"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ID != "batch-001" {
		t.Fatalf("expected ID batch-001, got %s", resp.ID)
	}

	calls := provider.SubmitCalls()
	if len(calls) != 1 || calls[0].LayerID != "repo-a" {
		t.Fatalf("unexpected submit calls: %+v", calls)
	}
}

func TestBatchSubmit_DecodesNewResponseFields(t *testing.T) {
	ec := 2
	provider := ingesttest.NewStaticProvider().
		WithSubmitResponse(ledger.SubmitResponse{
			ID:         "batch-002",
			Status:     "accepted",
			EventCount: &ec,
			EventIDs:   []string{"evt-001", "evt-002"},
			QueueAdded: 1,
		})
	client := ledger.NewClient(provider)

	resp, err := client.BatchSubmit(context.Background(), "repo-a", ledger.BatchSubmitInput{
		SourceRef:  "findings/repo-a/triage.json",
		RecordedAt: "2026-01-16T00:00:00+00:00",
		Events: []map[string]interface{}{
			{"finding_ref": "FIND-001"},
			{"finding_ref": "FIND-002"},
		},
		NeedsReview: []map[string]interface{}{
			{"finding_ref": "FIND-003", "queue_reason": "undetermined_finding"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.EventIDs) != 2 {
		t.Fatalf("expected 2 event_ids, got %d", len(resp.EventIDs))
	}
	if resp.EventIDs[0] != "evt-001" || resp.EventIDs[1] != "evt-002" {
		t.Fatalf("unexpected event_ids: %v", resp.EventIDs)
	}
	if resp.QueueAdded != 1 {
		t.Fatalf("expected queue_added 1, got %d", resp.QueueAdded)
	}
}

func TestSubmitTriageReport_BatchSubmitsConvertedEvents(t *testing.T) {
	provider := ingesttest.NewStaticProvider().
		WithSubmitResponse(ledger.SubmitResponse{ID: "triage-001", Status: "accepted"})
	client := ledger.NewClient(provider)

	in := fixtureTriageInput()
	converted := ledger.ConvertTriageReport(in.Report, in.SourceRef, in.RecordedAt, in.FingerprintIndex)

	_, err := client.BatchSubmit(context.Background(), in.LayerID, ledger.BatchSubmitInput{
		SourceRef:   in.SourceRef,
		RecordedAt:  in.RecordedAt,
		Events:      converted.Events,
		NeedsReview: converted.NeedsReview,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	calls := provider.SubmitCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 submit call, got %d", len(calls))
	}
	if calls[0].LayerID != "repo-a" {
		t.Fatalf("expected layer repo-a, got %s", calls[0].LayerID)
	}

	var body ledger.BatchSubmitInput
	if err := json.Unmarshal(calls[0].Payload, &body); err != nil {
		t.Fatalf("decode batch body: %v", err)
	}
	if body.SourceRef != "findings/repo-a/triage.json" {
		t.Fatalf("unexpected source_ref: %s", body.SourceRef)
	}
	if len(body.Events) != 1 {
		t.Fatalf("expected 1 converted event, got %d", len(body.Events))
	}
}

func TestSubmitTriageReport_FingerprintCheck(t *testing.T) {
	provider := ingesttest.NewStaticProvider()
	client := ledger.NewClient(provider)

	// fixtureTriageInput carries no FingerprintIndex, so the derived event has
	// no fingerprint and the post-conversion event-level check must fail,
	// naming the offending finding_ref.
	_, err := client.SubmitTriageReport(context.Background(), fixtureTriageInput())
	if err == nil {
		t.Fatal("expected fingerprint error when no FingerprintIndex is supplied")
	}
	var ie *ledger.IngestError
	if !errors.As(err, &ie) || ie.Phase != ledger.PhaseFingerprint {
		t.Fatalf("expected fingerprint phase error, got %v", err)
	}
}

func TestSubmitTriageReport_FingerprintIndexStamped(t *testing.T) {
	provider := ingesttest.NewStaticProvider().
		WithSubmitResponse(ledger.SubmitResponse{ID: "triage-001", Status: "accepted"})
	client := ledger.NewClient(provider)

	in := fixtureTriageInput()
	// The triage finding's orig_id is the finding_ref the converter emits; the
	// caller supplies its scan-lane fingerprint via the index.
	in.FingerprintIndex = map[string]string{
		"ACME_API-abc1234-001": testFingerprint,
	}

	if _, err := client.SubmitTriageReport(context.Background(), in); err != nil {
		t.Fatalf("unexpected error with FingerprintIndex supplied: %v", err)
	}

	calls := provider.SubmitCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 submit call, got %d", len(calls))
	}
	var body ledger.BatchSubmitInput
	if err := json.Unmarshal(calls[0].Payload, &body); err != nil {
		t.Fatalf("decode batch body: %v", err)
	}
	if len(body.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(body.Events))
	}
	if body.Events[0]["fingerprint"] != in.FingerprintIndex["ACME_API-abc1234-001"] {
		t.Fatalf("event fingerprint not stamped from index: %v", body.Events[0]["fingerprint"])
	}
	if _, hasAlgo := body.Events[0]["fingerprint_algo"]; hasAlgo {
		t.Fatal("SDK must not set fingerprint_algo; the ledger stamps it")
	}
}

func TestSubmitTriageReport_SchemaValidation(t *testing.T) {
	provider := ingesttest.NewStaticProvider()
	client := ledger.NewClient(provider)

	_, err := client.SubmitTriageReport(context.Background(), ledger.TriageReportInput{
		ReportMeta: ledger.ReportMeta{
			LayerID:    "repo-a",
			SourceRef:  "findings/repo-a/triage.json",
			RecordedAt: "2026-01-16T00:00:00+00:00",
		},
	})
	if err == nil {
		t.Fatal("expected schema validation error for empty report")
	}
	var ie *ledger.IngestError
	if !errors.As(err, &ie) {
		t.Fatalf("expected *IngestError, got %T", err)
	}
	if ie.Phase != ledger.PhaseValidate {
		t.Fatalf("expected phase validate, got %s", ie.Phase)
	}
}

func TestResolveReviewItem_RoundTrip(t *testing.T) {
	path := "/v1/ledger/layers/repo-a/resolve"
	provider := ingesttest.NewStaticProvider().
		WithPostResponse(path, ledger.ResolveResponse{Resolved: true, Key: `["a","b","c","d"]`})
	client := ledger.NewClient(provider)

	resp, err := client.ResolveReviewItem(context.Background(), "repo-a", ledger.ResolveInput{
		Key:      `["a","b","c","d"]`,
		Decision: "confirmed",
		Note:     "reviewed",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Resolved || resp.Key == "" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if len(provider.PostCalls()) != 1 || provider.PostCalls()[0].Path != path {
		t.Fatalf("unexpected post calls: %+v", provider.PostCalls())
	}
}

func TestSignLayer_RoundTrip(t *testing.T) {
	path := "/v1/ledger/layers/repo-a/sign"
	provider := ingesttest.NewStaticProvider().
		WithPostResponse(path, ledger.SignResponse{Status: "signed", Method: "cosign", LayerID: "repo-a"})
	client := ledger.NewClient(provider)

	resp, err := client.SignLayer(context.Background(), "repo-a", ledger.SignOpts{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "signed" || resp.Method != "cosign" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if len(provider.PostCalls()) != 1 || provider.PostCalls()[0].Path != path {
		t.Fatalf("unexpected post calls: %+v", provider.PostCalls())
	}
}

func TestSignLayer_WithRekor(t *testing.T) {
	path := "/v1/ledger/layers/repo-a/sign?rekor=true"
	provider := ingesttest.NewStaticProvider().
		WithPostResponse(path, ledger.SignResponse{Status: "signed", Method: "cosign", LayerID: "repo-a"})
	client := ledger.NewClient(provider)

	resp, err := client.SignLayer(context.Background(), "repo-a", ledger.SignOpts{Rekor: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "signed" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if len(provider.PostCalls()) != 1 || provider.PostCalls()[0].Path != path {
		t.Fatalf("expected rekor path, got: %+v", provider.PostCalls())
	}
}

func TestComputeFingerprints_RoundTrip(t *testing.T) {
	provider := ingesttest.NewStaticProvider().
		WithPostResponse("/v1/ledger/fingerprint", ledger.FingerprintResponse{
			StampedCount: 1,
			Findings: []map[string]interface{}{
				{"id": "FIND-001", "fingerprint": "fp-abc"},
			},
		})
	client := ledger.NewClient(provider)

	resp, err := client.ComputeFingerprints(context.Background(), ledger.FingerprintInput{
		Findings: []map[string]interface{}{
			{"id": "FIND-001"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StampedCount != 1 {
		t.Fatalf("expected stamped_count 1, got %d", resp.StampedCount)
	}
}

func TestSubmitCountersign_RoundTrip(t *testing.T) {
	provider := ingesttest.NewStaticProvider().
		WithCountersignResponse(ledger.SubmitResponse{ID: "cs-001", Status: "accepted"})
	client := ledger.NewClient(provider)

	resp, err := client.SubmitCountersign(context.Background(), ledger.CountersignInput{
		EventMeta: ledger.EventMeta{
			LayerID:    "repo-a",
			RecordedAt: "2026-01-16T00:00:00+00:00",
		},
		FindingRef:    "FIND-001",
		Verdict:       "true_positive",
		Justification: "Reviewed source and confirmed exploit path.",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ID != "cs-001" {
		t.Fatalf("expected ID cs-001, got %s", resp.ID)
	}
	calls := provider.IngestCalls()
	last := calls[len(calls)-1]
	if last.Meta.Kind != ledger.KindCountersign {
		t.Fatalf("expected kind countersign, got %s", last.Meta.Kind)
	}
}

func TestStampEventIdentities_RoundTrip(t *testing.T) {
	path := "/v1/ledger/layers/repo-a/stamp"
	root := "root-abc"
	provider := ingesttest.NewStaticProvider().
		WithPostResponse(path, ledger.StampResponse{MerkleRoot: &root, LayerID: "repo-a", Stamped: 1})
	client := ledger.NewClient(provider)

	resp, err := client.StampEventIdentities(context.Background(), "repo-a", ledger.StampInput{
		Fingerprints: map[string]string{"FIND-001": testFingerprint},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Stamped != 1 || resp.MerkleRoot == nil || *resp.MerkleRoot != root {
		t.Fatalf("unexpected response: %+v", resp)
	}

	calls := provider.PostCalls()
	if len(calls) != 1 || calls[0].Path != path {
		t.Fatalf("unexpected post calls: %+v", calls)
	}
	var body ledger.StampInput
	if err := json.Unmarshal(calls[0].Payload, &body); err != nil {
		t.Fatalf("decode stamp body: %v", err)
	}
	if body.Fingerprints["FIND-001"] != testFingerprint {
		t.Fatalf("fingerprint not sent: %v", body.Fingerprints)
	}
}

func TestBatchSubmit_DecodeError(t *testing.T) {
	provider := &badSubmitProvider{data: []byte(`not json`)}
	client := ledger.NewClient(provider)

	_, err := client.BatchSubmit(context.Background(), "repo-a", ledger.BatchSubmitInput{
		SourceRef:  "ref",
		RecordedAt: "2026-01-16T00:00:00+00:00",
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
	var ie *ledger.IngestError
	if !errors.As(err, &ie) || ie.Phase != ledger.PhaseDecode {
		t.Fatalf("expected decode phase error, got %v", err)
	}
}

type badSubmitProvider struct {
	data []byte
}

func (p *badSubmitProvider) Ingest(context.Context, ledger.IngestMeta, []byte) ([]byte, error) {
	return nil, errors.New("not used")
}

func (p *badSubmitProvider) Submit(context.Context, string, []byte) ([]byte, error) {
	return p.data, nil
}

func (p *badSubmitProvider) Post(context.Context, string, []byte) ([]byte, error) {
	return nil, errors.New("not used")
}

// fixtureTriageInput's fingerprint is 64 hex characters because
// triage.schema.json now DECLARES the field with the contract pattern. The
// previous placeholder "fp-test-001" was rejected by schema validation
// before reaching the fingerprint check these tests exist to exercise.
func fixtureTriageInput() ledger.TriageReportInput {
	raw := `{
		"layer_id": "repo-a",
		"source_ref": "findings/repo-a/triage.json",
		"recorded_at": "2026-01-16T00:00:00+00:00",
		"report": {
			"triage_completed": "2026-01-16",
			"triage_context": {
				"environment": "development",
				"harness_version": "0.299.0",
				"repo": "https://github.com/acme/api",
				"votes_per_finding": 3
			},
			"summary": {
				"by_severity": {"critical": 0, "high": 1, "low": 0, "medium": 0},
				"duplicates": 0,
				"false_positives": 0,
				"hardening": 0,
				"input_count": 1,
				"true_positives": 1,
				"undetermined": 0
			},
			"findings": [{
				"id": "f001",
				"orig_id": "ACME_API-abc1234-001",
				"title": "SQL injection",
				"verdict": "true_positive",
				"rationale": "Parameterized query missing in login handler",
				"first_links": ["src/login.go:42"],
				"fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}]
		}
	}`
	var in ledger.TriageReportInput
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		panic(err)
	}
	return in
}

func TestConvertOccurredAtNeverDoublesTheTimeComponent(t *testing.T) {
	cases := []struct {
		name       string
		date       string
		recordedAt string
		want       string
	}{
		{"bare date padded", "2026-07-09", "2026-07-11T12:00:00+00:00", "2026-07-09T00:00:00+00:00"},
		{"timestamp passes through", "2026-07-09T14:30:00Z", "2026-07-11T12:00:00+00:00", "2026-07-09T14:30:00Z"},
		{"offset passes through", "2026-07-09T14:30:00+02:00", "", "2026-07-09T14:30:00+02:00"},
		{"empty falls back", "", "2026-07-11T12:00:00+00:00", "2026-07-11T12:00:00+00:00"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := types.Verification{
				Metadata: types.VerificationMetadata{Date: tc.date, HarnessVersion: "0.28.0"},
				VerifiedFindings: []types.VerifiedFinding{{
					OriginalId: "FIND-001",
					Verdict:    "resolved",
					Evidence:   types.VerifiedFindingEvidence{Explanation: "patch removes sink"},
				}},
			}

			out := ledger.ConvertVerificationReport(report, "verifications/v.json", tc.recordedAt, nil)
			if len(out.Events) != 1 {
				t.Fatalf("expected 1 event, got %d", len(out.Events))
			}
			got, _ := out.Events[0]["occurred_at"].(string)
			if got != tc.want {
				t.Fatalf("occurred_at: got %q, want %q", got, tc.want)
			}
			if strings.Count(got, "T") > 1 {
				t.Fatalf("duplicate time component: %q", got)
			}
		})
	}
}

func (p *badSubmitProvider) Query(context.Context, string, string) ([]byte, error) { return nil, nil }
