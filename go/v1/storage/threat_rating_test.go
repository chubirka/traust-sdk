package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
)

// The OWASP Risk Rating Methodology's worked example: likelihood 4.375
// (medium), technical impact 7.25 (high), severity high.
const owaspWorkedExample = `{
  "method": "owasp-risk-rating",
  "likelihood": {"factors": {"skill_level": 5, "motive": 2, "opportunity": 7,
    "population_size": 1, "ease_of_discovery": 3, "ease_of_exploit": 6,
    "awareness": 9, "intrusion_detection": 2}, "score": 4.375, "level": "medium"},
  "impact": {"basis": "technical", "technical": {"confidentiality": 9,
    "integrity": 7, "availability": 5, "accountability": 8},
    "score": 7.25, "level": "high"},
  "severity": "high",
  "rationale": {"awareness": "the pattern is publicly documented"}
}`

// ratedThreatModel is the sample model with T2 re-rated: T1 keeps its
// legacy labels, so one model carries both kinds, as every model does
// between its first OWASP pass and its last legacy row.
func ratedThreatModel(t *testing.T) []byte {
	t.Helper()
	var model map[string]any
	if err := json.Unmarshal(sampleArtifacts(t)["threat-model"], &model); err != nil {
		t.Fatal(err)
	}
	threats := model["threats"].([]any)
	t2 := threats[1].(map[string]any)
	delete(t2, "impact")
	delete(t2, "likelihood")
	var rating map[string]any
	if err := json.Unmarshal([]byte(owaspWorkedExample), &rating); err != nil {
		t.Fatal(err)
	}
	t2["risk_rating"] = rating
	payload, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestThreatProjectionCarriesOwaspRating(t *testing.T) {
	ctx := context.Background()
	client := openTestStorage(t)
	if _, err := client.saveNamed(ctx, "threat-model", ratedThreatModel(t), bindingFor("threat-model")); err != nil {
		t.Fatal(err)
	}
	type row struct {
		severity, likelihoodLevel, impactLevel, impactBasis, riskRating sql.NullString
		likelihoodScore, impactScore                                    sql.NullFloat64
		impact, likelihood                                              sql.NullString
		score                                                           sql.NullInt64
	}
	read := func(id string) row {
		var r row
		if err := sqlDB(client).QueryRow(
			`SELECT severity, likelihood_level, impact_level, impact_basis, risk_rating,
			        likelihood_score, impact_score, impact, likelihood, score
			 FROM threat WHERE threat_id = ?`, id,
		).Scan(&r.severity, &r.likelihoodLevel, &r.impactLevel, &r.impactBasis, &r.riskRating,
			&r.likelihoodScore, &r.impactScore, &r.impact, &r.likelihood, &r.score); err != nil {
			t.Fatal(err)
		}
		return r
	}

	rated := read("T2")
	if rated.severity.String != "high" || rated.likelihoodLevel.String != "medium" ||
		rated.impactLevel.String != "high" || rated.impactBasis.String != "technical" ||
		rated.likelihoodScore.Float64 != 4.375 || rated.impactScore.Float64 != 7.25 {
		t.Fatalf("rated threat columns = %+v", rated)
	}
	var stored map[string]any
	if err := json.Unmarshal([]byte(rated.riskRating.String), &stored); err != nil {
		t.Fatalf("risk_rating JSON: %v", err)
	}
	if stored["rationale"].(map[string]any)["awareness"] != "the pattern is publicly documented" {
		t.Fatalf("risk_rating lost its reasons: %v", stored)
	}
	if rated.impact.Valid || rated.likelihood.Valid || rated.score.Valid {
		t.Fatalf("a rated threat has no legacy labels or legacy score: %+v", rated)
	}

	legacy := read("T1")
	if legacy.severity.Valid || legacy.riskRating.Valid || legacy.likelihoodScore.Valid {
		t.Fatalf("an unrated threat has no rating columns: %+v", legacy)
	}
	if !legacy.impact.Valid || !legacy.likelihood.Valid || !legacy.score.Valid {
		t.Fatalf("an unrated threat keeps its legacy labels and score: %+v", legacy)
	}
}
