package ledger

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/traust-security/traust-sdk/go/v1/enums"
	"github.com/traust-security/traust-sdk/go/v1/types"
)

const rationaleCap = 500

// ConvertResult holds events and queue items produced from a report.
type ConvertResult struct {
	Events      []map[string]interface{}
	NeedsReview []map[string]interface{}
	Skipped     []map[string]interface{}
}

// stampFingerprint sets event["fingerprint"] from the caller-supplied index
// when a non-empty fingerprint is known for the finding reference. The SDK
// never computes fingerprints (that is the ledger's identity recipe) and never
// sets fingerprint_algo (the ledger stamps the algo version server-side).
func stampFingerprint(event map[string]interface{}, fpIndex map[string]string, ref string) {
	if fp, ok := fpIndex[ref]; ok && fp != "" {
		event["fingerprint"] = fp
	}
}

// ConvertTriageReport maps a triage report to ledger events and needs_review items.
// The server stamps event_id and actor identity; events are submitted without event_id.
// fpIndex maps finding_ref to the ledger-computed fingerprint (from the scan
// report); each derived event is stamped with its finding's fingerprint.
func ConvertTriageReport(report types.Triage, sourceRef, recordedAt string, fpIndex map[string]string) ConvertResult {
	occurredAt := eventOccurredAt(report.TriageCompleted, recordedAt)
	source := map[string]interface{}{
		"type": "triage_report",
		"ref":  sourceRef,
	}

	result := ConvertResult{
		Events:      make([]map[string]interface{}, 0),
		NeedsReview: make([]map[string]interface{}, 0),
		Skipped:     make([]map[string]interface{}, 0),
	}

	for _, finding := range report.Findings {
		if finding.Verdict == enums.VerdictDuplicate {
			continue
		}

		ref := stringish(finding.OrigId)
		if ref == "" {
			result.Skipped = append(result.Skipped, map[string]interface{}{
				"id":      finding.Id,
				"verdict": finding.Verdict,
				"reason":  "missing orig_id",
			})
			continue
		}

		if finding.Verdict == enums.VerdictUndetermined {
			result.NeedsReview = append(result.NeedsReview, undeterminedReviewItem(
				sourceRef, ref, stringish(finding.Rationale),
			))
			continue
		}

		validity, ok := triageValidity(finding.Verdict)
		if !ok {
			result.Skipped = append(result.Skipped, map[string]interface{}{
				"id":      finding.Id,
				"verdict": finding.Verdict,
				"reason":  "unknown verdict",
			})
			continue
		}

		event := map[string]interface{}{
			"finding_ref":   ref,
			"recorded_at":   recordedAt,
			"occurred_at":   occurredAt,
			"source":        source,
			"disposition":   map[string]interface{}{"validity": validity},
			"rationale":     squash(stringish(finding.Rationale), rationaleCap),
			"evidence_refs": finding.FirstLinks,
		}
		stampFingerprint(event, fpIndex, ref)
		result.Events = append(result.Events, event)
	}

	return result
}

// ConvertValidationReport maps a validation report to ledger events.
// fpIndex maps finding_ref to the ledger-computed fingerprint.
//
// The report's own soundness and grade stamps are honoured, as the Python
// emitter does: a refuted (or inconclusive) finding carrying a soundness_flag
// rests on a probe that never soundly tested the claim, so it queues an
// unsound_refutation item instead of becoming a false_positive event. An
// E3 (inference-only) confirmation queues weak_confirmation instead of a
// confirmed event. Every event carries its evidence_grade, which the ledger
// uses to demote E2/E3 execution evidence below class 1.
func ConvertValidationReport(report types.Validation, sourceRef, recordedAt string, fpIndex map[string]string) ConvertResult {
	occurredAt := eventOccurredAt(report.Metadata.Date, recordedAt)
	source := map[string]interface{}{
		"type": "validation_report",
		"ref":  sourceRef,
	}

	result := ConvertResult{
		Events:      make([]map[string]interface{}, 0),
		NeedsReview: make([]map[string]interface{}, 0),
	}

	for _, finding := range report.ValidatedFindings {
		flag := strings.TrimSpace(ptrString(finding.SoundnessFlag))
		gradable := finding.Verdict == enums.ValidationVerdictConfirmed ||
			finding.Verdict == enums.ValidationVerdictRefuted
		if !gradable && !(finding.Verdict == enums.ValidationVerdictInconclusive && flag != "") {
			continue
		}

		ref := validationFindingRef(finding)
		if ref == "" {
			continue
		}

		if flag != "" && finding.Verdict != enums.ValidationVerdictConfirmed {
			result.NeedsReview = append(result.NeedsReview, validationReviewItem(
				sourceRef, ref, enums.LayerReviewQueueReasonUnsoundRefutation,
				fmt.Sprintf("machine refutation blocked by the soundness gate (%s) — the probe "+
					"never soundly tested the claim; observed: %s",
					flag, firstNonEmpty(ptrString(finding.ObservedImpact), "(no output)")),
			))
			continue
		}

		grade := strings.TrimSpace(ptrString(finding.EvidenceGrade))
		if finding.Verdict == enums.ValidationVerdictConfirmed && grade == "E3" {
			result.NeedsReview = append(result.NeedsReview, validationReviewItem(
				sourceRef, ref, enums.LayerReviewQueueReasonWeakConfirmation,
				"E3 inference-only confirmation — grade the evidence or re-probe for an "+
					"observed effect: "+firstNonEmpty(ptrString(finding.ObservedImpact), "(no output)"),
			))
			continue
		}

		validity := "confirmed"
		if finding.Verdict == enums.ValidationVerdictRefuted {
			validity = "false_positive"
		}

		event := map[string]interface{}{
			"finding_ref":   ref,
			"recorded_at":   recordedAt,
			"occurred_at":   occurredAt,
			"source":        source,
			"disposition":   map[string]interface{}{"validity": validity},
			"rationale":     buildValidationRationale(finding),
			"evidence_refs": []string{},
		}
		if grade != "" {
			event["evidence_grade"] = grade
		}
		stampFingerprint(event, fpIndex, ref)
		result.Events = append(result.Events, event)
	}

	return result
}

func validationReviewItem(sourceRef, findingRef string, reason enums.LayerReviewQueueReason, quote string) map[string]interface{} {
	return map[string]interface{}{
		"source_ref":            sourceRef,
		"suggested_finding_ref": findingRef,
		"queue_reason":          string(reason),
		"quote":                 squash(quote, rationaleCap),
	}
}

// ConvertVerificationReport maps a verification report to ledger events.
// fpIndex maps finding_ref to the ledger-computed fingerprint.
func ConvertVerificationReport(report types.Verification, sourceRef, recordedAt string, fpIndex map[string]string) ConvertResult {
	occurredAt := eventOccurredAt(report.Metadata.Date, recordedAt)
	source := map[string]interface{}{
		"type": "verification_report",
		"ref":  sourceRef,
	}

	result := ConvertResult{
		Events:  make([]map[string]interface{}, 0),
		Skipped: make([]map[string]interface{}, 0),
	}

	for _, finding := range report.VerifiedFindings {
		ref := strings.TrimSpace(finding.OriginalId)
		if ref == "" {
			result.Skipped = append(result.Skipped, map[string]interface{}{
				"id":      "",
				"verdict": finding.Verdict,
				"reason":  "empty original_id",
			})
			continue
		}

		disposition, ok := verificationDisposition(finding)
		if !ok {
			result.Skipped = append(result.Skipped, map[string]interface{}{
				"id":      ref,
				"verdict": finding.Verdict,
				"reason":  "unknown verdict",
			})
			continue
		}

		event := map[string]interface{}{
			"finding_ref":   ref,
			"recorded_at":   recordedAt,
			"occurred_at":   occurredAt,
			"source":        source,
			"disposition":   disposition,
			"rationale":     squash(finding.Evidence.Explanation, rationaleCap),
			"evidence_refs": []string{},
		}
		stampFingerprint(event, fpIndex, ref)
		result.Events = append(result.Events, event)
	}

	return result
}

func verificationDisposition(finding types.VerifiedFinding) (map[string]interface{}, bool) {
	switch finding.Verdict {
	case "resolved", "new_approach":
		return map[string]interface{}{
			"resolution": string(enums.DispositionResolutionResolved),
		}, true
	case "partially_resolved":
		resolution := enums.DispositionResolutionPartiallyResolved
		if finding.CrossRepo != nil && finding.CrossRepo.Propagation == "pending" {
			resolution = enums.DispositionResolutionFixInProgress
		}
		return map[string]interface{}{
			"resolution": string(resolution),
		}, true
	case "unresolved":
		return map[string]interface{}{
			"resolution": string(enums.DispositionResolutionOpen),
		}, true
	case "regression":
		return map[string]interface{}{
			"resolution": string(enums.DispositionResolutionRegressionIntroduced),
		}, true
	case "risk_accepted":
		return map[string]interface{}{
			"resolution": string(enums.DispositionResolutionRiskAccepted),
		}, true
	case "false_positive":
		return map[string]interface{}{
			"validity": string(enums.ValidityFalsePositive),
		}, true
	default:
		return nil, false
	}
}

func triageValidity(verdict enums.Verdict) (string, bool) {
	switch verdict {
	case enums.VerdictTruePositive:
		return "confirmed", true
	case enums.VerdictHardening:
		return "hardening", true
	case enums.VerdictFalsePositive:
		return "false_positive", true
	default:
		return "", false
	}
}

// eventOccurredAt derives an event's occurred_at from a report's own date
// field, falling back to the submission's recordedAt.
//
// Report dates are contractually YYYY-MM-DD, but producers pass full
// timestamps. Appending the midnight suffix unconditionally produced
// "2026-01-16T00:00:00ZT00:00:00+00:00", which the ledger stores without
// complaint and then cannot read back.
func eventOccurredAt(reportDate, recordedAt string) string {
	date := reportDate
	if date == "" {
		date = recordedAt
	}
	if strings.ContainsAny(date, "Tt") {
		return date
	}
	if len(date) > 10 {
		date = date[:10]
	}
	return date + "T00:00:00+00:00"
}

func undeterminedReviewItem(sourceRef, findingRef, rationale string) map[string]interface{} {
	quote := squash(rationale, rationaleCap)
	if quote != "" {
		quote += " "
	}
	quote += "(triage: undetermined — nothing proven or refuted; human review required)"
	return map[string]interface{}{
		"source_ref":            sourceRef,
		"suggested_finding_ref": findingRef,
		"queue_reason":          "undetermined_finding",
		"quote":                 squash(quote, rationaleCap),
	}
}

func validationFindingRef(finding types.ValidatedFinding) string {
	raw, err := json.Marshal(finding)
	if err != nil {
		return strings.TrimSpace(finding.SourceId)
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return strings.TrimSpace(finding.SourceId)
	}
	for _, key := range []string{"finding_ref", "id", "source_id"} {
		if s := stringish(fields[key]); s != "" {
			return s
		}
	}
	return ""
}

func buildValidationRationale(finding types.ValidatedFinding) string {
	technique := finding.Technique
	if technique == "" {
		technique = "replay"
	}

	var detail string
	if finding.Verdict == enums.ValidationVerdictConfirmed {
		detail = firstNonEmpty(ptrString(finding.ObservedImpact), ptrString(finding.DeviationFromClaim), "see evidence artifacts")
		return squash(fmt.Sprintf("live validation (%s): confirmed — %s", technique, detail), rationaleCap)
	}

	detail = firstNonEmpty(ptrString(finding.DeviationFromClaim), ptrString(finding.ObservedImpact), "claim did not reproduce against the live target")
	return squash(fmt.Sprintf("live validation (%s): refuted — %s", technique, detail), rationaleCap)
}

func squash(text string, cap int) string {
	if cap <= 0 {
		return ""
	}
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return ""
	}
	joined := strings.Join(fields, " ")
	if len(joined) <= cap {
		return joined
	}
	return joined[:cap]
}

func stringish(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func ptrString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
