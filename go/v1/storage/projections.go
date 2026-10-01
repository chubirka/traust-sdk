package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/traust-security/traust-sdk/go/v1/types"
)

type projectionName string

type projectionField string

const (
	projectionFieldOriginalID projectionField = "orig_id"
	projectionFieldRow        projectionField = "row"
)

func indexedProjectionField(field projectionField, index int) projectionField {
	return projectionField(fmt.Sprintf("%s[%d]", field, index))
}

func projectionText(value any) (string, error) {
	text, ok := value.(string)
	if !ok {
		return "", errors.New("expected string")
	}
	return text, nil
}

func optionalProjectionText(value any) (*string, error) {
	if value == nil {
		return nil, nil
	}
	if text, ok := value.(*string); ok {
		return text, nil
	}
	text, err := projectionText(value)
	if err != nil {
		return nil, err
	}
	return &text, nil
}

func projectionJSON(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode JSON: %w", err)
	}
	return string(payload), nil
}

func optionalProjectionJSON(value any) (*string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode JSON: %w", err)
	}
	if string(payload) == "null" {
		return nil, nil
	}
	text := string(payload)
	return &text, nil
}

func projectionInteger(value any) (*int64, error) {
	if value == nil {
		return nil, nil
	}
	var text string
	switch number := value.(type) {
	case json.Number:
		text = number.String()
	case float64:
		if math.IsInf(number, 0) || math.IsNaN(number) || math.Trunc(number) != number {
			return nil, errors.New("expected integer")
		}
		text = strconv.FormatFloat(number, 'f', -1, 64)
	case int:
		integer := int64(number)
		return &integer, nil
	case int64:
		return &number, nil
	default:
		return nil, errors.New("expected integer")
	}
	integer, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		floating, floatErr := strconv.ParseFloat(text, 64)
		if floatErr != nil || math.Trunc(floating) != floating || floating > math.MaxInt64 || floating < math.MinInt64 {
			return nil, errors.New("expected integer")
		}
		integer = int64(floating)
	}
	return &integer, nil
}

func (s *sqlStore) projectLayer(
	ctx context.Context,
	conn *sql.Conn,
	state writeState,
	layer types.Layer,
) error {
	// The events are the TIME DIMENSION. A Go caller that saves a layer
	// without them writes the merkle root and silently loses every date the
	// trend, MTTR and SLA views are computed from.
	for _, event := range layer.Events {
		source := string(event.Source.Type)
		actorKind := string(event.Source.Actor.Kind)
		var validity, resolution *string
		if event.Disposition.Validity != nil {
			value := string(*event.Disposition.Validity)
			validity = &value
		}
		if event.Disposition.Resolution != nil {
			value := string(*event.Disposition.Resolution)
			resolution = &value
		}
		if err := s.queries.layerEventUpsert(ctx, conn, layerEventUpsertParams{
			bindingId:       state.bindingID,
			artifactDigest:  state.digest,
			eventId:         event.EventId,
			findingRef:      event.FindingRef,
			fingerprint:     event.Fingerprint,
			fingerprintAlgo: event.FingerprintAlgo,
			recordedAt:      event.RecordedAt,
			occurredAt:      event.OccurredAt,
			sourceType:      &source,
			sourceRef:       &event.Source.Ref,
			actorKind:       &actorKind,
			validity:        validity,
			resolution:      resolution,
			evidenceGrade:   event.EvidenceGrade,
			autoAcceptTier:  optionalBoolAsInt(event.AutoAcceptTier),
		}); err != nil {
			return projectionError(projectionLayerEvent, projectionFieldRow, err)
		}
	}
	return nil
}

func (s *sqlStore) projectVulnFindings(
	ctx context.Context,
	conn *sql.Conn,
	state writeState,
	document types.VulnFindings,
) error {
	for index, finding := range document.Findings {
		line, err := projectionInteger(finding.Line)
		if err != nil {
			return projectionError(projectionFinding, indexedProjectionField(projectionFieldLine, index), err)
		}
		category := finding.Category
		if err := s.queries.findingUpsert(ctx, conn, findingUpsertParams{
			bindingId:      state.bindingID,
			artifactDigest: state.digest,
			findingId:      finding.Id,
			target:         document.Target,
			scannedAt:      document.ScannedAt,
			title:          finding.Title,
			severity:       string(finding.Severity),
			description:    finding.Description,
			category:       &category,
			file:           finding.File,
			line:           line,
			cwe:            finding.Cwe,
			recommendation: finding.Recommendation,
			confidence:     finding.Confidence,
		}); err != nil {
			return projectionError(projectionFinding, indexedProjectionField(projectionFieldRow, index), err)
		}
	}
	return nil
}

func (s *sqlStore) projectTriage(
	ctx context.Context,
	conn *sql.Conn,
	state writeState,
	document types.Triage,
) error {
	for index, finding := range document.Findings {
		sourceFindingID, err := optionalProjectionText(finding.OrigId)
		if err != nil {
			return projectionError(projectionTriageVerdict, indexedProjectionField(projectionFieldOriginalID, index), err)
		}
		severity, err := optionalProjectionText(finding.Severity)
		if err != nil {
			return projectionError(projectionTriageVerdict, indexedProjectionField(projectionFieldSeverity, index), err)
		}
		voteBreakdown, err := optionalProjectionJSON(finding.VoteBreakdown)
		if err != nil {
			return projectionError(projectionTriageVerdict, indexedProjectionField(projectionFieldVoteBreakdown, index), err)
		}
		rationale, err := optionalProjectionText(finding.Rationale)
		if err != nil {
			return projectionError(projectionTriageVerdict, indexedProjectionField(projectionFieldRationale, index), err)
		}
		if err := s.queries.triageVerdictUpsert(ctx, conn, triageVerdictUpsertParams{
			bindingId:       state.bindingID,
			artifactDigest:  state.digest,
			findingId:       finding.Id,
			sourceFindingId: sourceFindingID,
			triageCompleted: document.TriageCompleted,
			verdict:         string(finding.Verdict),
			severity:        severity,
			voteBreakdown:   voteBreakdown,
			rationale:       rationale,
		}); err != nil {
			return projectionError(projectionTriageVerdict, indexedProjectionField(projectionFieldRow, index), err)
		}
	}
	return nil
}

// projectCorpusRegistry fans a registry out to one subject_ownership row per
// subject. Hand-written because the generator's one-row projector maps ROOT
// schema properties to columns, and these live inside subjects[].
//
// Ownership is the denominator every dashboard cut divides by, so a Go
// caller that saves a registry without this writes the evidence and leaves
// every owned-scoped query empty.
func (s *sqlStore) projectCorpusRegistry(
	ctx context.Context,
	conn *sql.Conn,
	state writeState,
	registry types.CorpusRegistry,
) error {
	for _, subject := range registry.Subjects {
		var refKind *string
		if subject.RefKind != nil {
			value := string(*subject.RefKind)
			refKind = &value
		}
		if err := s.queries.subjectOwnershipUpsert(ctx, conn, subjectOwnershipUpsertParams{
			bindingId:      state.bindingID,
			artifactDigest: state.digest,
			subjectId:      subject.SubjectId,
			tree:           subject.Tree,
			ownership:      string(subject.Ownership),
			businessUnit:   subject.BusinessUnit,
			label:          subject.Label,
			product:        subject.Product,
			repoUrl:        subject.RepoUrl,
			ref:            subject.Ref,
			refKind:        refKind,
			isBranchAudit:  optionalBoolAsInt(subject.IsBranchAudit),
		}); err != nil {
			return projectionError(projectionSubjectOwnership, projectionFieldRow, err)
		}
	}
	return nil
}

// optionalBoolAsInt keeps absent ABSENT. storage/v1 stores flags as INTEGER
// on both dialects, and "not a branch audit" must not be confused with "the
// registry does not say".
func optionalBoolAsInt(value *bool) *int64 {
	if value == nil {
		return nil
	}
	stored := int64(0)
	if *value {
		stored = 1
	}
	return &stored
}

// : impact weight x likelihood weight. Must stay identical to the Python
// : side's _IMPACT_WEIGHT/_LIKELIHOOD_WEIGHT -- the two projectors write the
// : same column and a divergence here is a silent cross-language disagreement
// : about rank order.
var threatImpactWeight = map[string]int64{
	"low": 1, "medium": 2, "high": 4, "critical": 8, "existential": 16,
}

var threatLikelihoodWeight = map[string]int64{
	"very_rare": 1, "rare": 2, "possible": 4, "likely": 8, "almost_certain": 16,
}

// threatScore is nil when either enum is unrateable. Zero would claim
// "rated, and it came out lowest"; both enums are required, so an
// unrecognised value means the model is off-contract and the ordering has
// nothing to say about it.
func threatScore(impact, likelihood string) *int64 {
	left, okLeft := threatImpactWeight[impact]
	right, okRight := threatLikelihoodWeight[likelihood]
	if !okLeft || !okRight {
		return nil
	}
	product := left * right
	return &product
}

// threatRating holds an OWASP risk rating's threat columns: the whole block
// (factors and reasons are part of the contract) and its derived values,
// typed so a view can filter and order on them. All nil when unrated.
type threatRating struct {
	riskRating      *string
	severity        *string
	likelihoodScore *float64
	likelihoodLevel *string
	impactScore     *float64
	impactLevel     *string
	impactBasis     *string
}

func threatRatingColumns(rating *types.OwaspRiskRating) (threatRating, error) {
	if rating == nil {
		return threatRating{}, nil
	}
	block, err := optionalProjectionJSON(rating)
	if err != nil {
		return threatRating{}, err
	}
	severity := string(rating.Severity)
	likelihoodScore := rating.Likelihood.Score
	likelihoodLevel := string(rating.Likelihood.Level)
	impactScore := rating.Impact.Score
	impactLevel := string(rating.Impact.Level)
	impactBasis := string(rating.Impact.Basis)
	return threatRating{
		riskRating:      block,
		severity:        &severity,
		likelihoodScore: &likelihoodScore,
		likelihoodLevel: &likelihoodLevel,
		impactScore:     &impactScore,
		impactLevel:     &impactLevel,
		impactBasis:     &impactBasis,
	}, nil
}

// projectThreatModel fans a model out to one `threat` row per threat.
// Hand-written for the same reason projectCorpusRegistry is: the generator's
// one-row projector maps ROOT schema properties to columns, and these live
// inside threats[].
//
// Keyed on `<subject>:<id>`, never on Id alone: every model numbers its
// threats from T1, so an Id-keyed write would keep one threat per number
// across the whole estate.
//
// The family was threat-register until contracts 0.24.0. Threat models had no
// JSON form then, so the only structured artifact was a register a parser
// emitted; they have one now and the model itself is the artifact.
func (s *sqlStore) projectThreatModel(
	ctx context.Context,
	conn *sql.Conn,
	state writeState,
	model types.ThreatModel,
) error {
	subjectID := state.binding.SubjectID
	if subjectID == nil {
		subjectID = model.SubjectId
	}
	keyPrefix := model.System
	if subjectID != nil {
		keyPrefix = *subjectID
	}
	modelName := model.Provenance.Target
	if modelName == "" {
		modelName = model.System
	}
	product := model.System

	for _, threat := range model.Threats {
		if threat.Id == "" {
			continue
		}
		actors, err := optionalProjectionJSON(threat.Actor)
		if err != nil {
			return projectionError(projectionThreat, projectionFieldActors, err)
		}
		// Kept even when empty: an empty list means MODELLED BUT NOT
		// EVIDENCED, which is a different claim from unmitigated, and
		// threat_exposure reports the two apart.
		evidence, err := optionalProjectionJSON(threat.Evidence)
		if err != nil {
			return projectionError(projectionThreat, projectionFieldEvidence, err)
		}
		dimensions, err := optionalProjectionJSON(threat.IsolationDimensions)
		if err != nil {
			return projectionError(projectionThreat, projectionFieldIsolationDimensions, err)
		}
		attackRefs, err := optionalProjectionJSON(threat.AttackRefs)
		if err != nil {
			return projectionError(projectionThreat, projectionFieldAttackRefs, err)
		}
		// Legacy labels: present only on a threat not yet re-rated with the
		// OWASP Risk Rating Methodology. The legacy score orders those
		// threats; a rated one orders by severity and has no score.
		var impact, likelihood *string
		if threat.Impact != nil {
			value := string(*threat.Impact)
			impact = &value
		}
		if threat.Likelihood != nil {
			value := string(*threat.Likelihood)
			likelihood = &value
		}
		var score *int64
		if threat.RiskRating == nil && impact != nil && likelihood != nil {
			score = threatScore(*impact, *likelihood)
		}
		rating, err := threatRatingColumns(threat.RiskRating)
		if err != nil {
			return projectionError(projectionThreat, projectionFieldRow, err)
		}
		status := string(threat.Status)
		statement := threat.Threat
		linddun := int64(0)
		if strings.HasPrefix(strings.ToLower(statement), "linddun:") {
			linddun = 1
		}
		if err := s.queries.threatUpsert(ctx, conn, threatUpsertParams{
			bindingId:       state.bindingID,
			artifactDigest:  state.digest,
			threatKey:       keyPrefix + ":" + threat.Id,
			threatId:        threat.Id,
			model:           modelName,
			subjectId:       subjectID,
			product:         &product,
			statement:       &statement,
			surface:         threat.Surface,
			asset:           threat.Asset,
			impact:          impact,
			likelihood:      likelihood,
			riskRating:      rating.riskRating,
			severity:        rating.severity,
			likelihoodScore: rating.likelihoodScore,
			likelihoodLevel: rating.likelihoodLevel,
			impactScore:     rating.impactScore,
			impactLevel:     rating.impactLevel,
			impactBasis:     rating.impactBasis,
			status:          &status,
			controls:        threat.Controls,
			actors:          actors,
			evidence:        evidence,
			linddun:         &linddun,
			score:           score,
			attackRefs:      attackRefs,
			// threat-model.schema.json declares no isolation_boundaries on a
			// threat; the column exists for the tenant-boundary work and the
			// Python projector writes nil here too.
			isolationBoundaries: nil,
			isolationDimensions: dimensions,
		}); err != nil {
			return projectionError(projectionThreat, projectionFieldRow, err)
		}
	}
	return nil
}

// optionalIntAsInt64 keeps absent ABSENT, matching optionalBoolAsInt: a
// missing score is not a score of zero.
func optionalIntAsInt64(value *int) *int64 {
	if value == nil {
		return nil
	}
	stored := int64(*value)
	return &stored
}
