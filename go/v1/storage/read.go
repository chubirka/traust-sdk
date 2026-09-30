package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"

	"github.com/traust-security/traust-sdk/go/v1/types"
)

type FindingsSummaryRow struct {
	ScopeID      string
	SubjectID    *string
	RunID        *string
	LayerID      *string
	Repository   *string
	Severity     string
	Verdict      *string
	FindingCount int64
}

func (c *Client) GetEvidence(ctx context.Context, digest string) ([]byte, error) {
	if c == nil || c.store == nil {
		return nil, wrap(OperationRead, PhaseInput, ErrNilDatabase)
	}
	if !digestPattern.MatchString(digest) {
		return nil, wrap(OperationRead, PhaseInput, ErrNotFound)
	}
	conn, err := c.store.db.Conn(ctx)
	if err != nil {
		return nil, wrap(OperationRead, PhaseConnect, err)
	}
	defer func() { _ = conn.Close() }()
	return c.store.readEvidence(ctx, conn, ObjectMeta{Digest: digest, ContractsVersion: storageFormatVersion})
}

func (c *Client) GetBinding(ctx context.Context, bindingID string) (BindingRecord, error) {
	if c == nil || c.store == nil {
		return BindingRecord{}, wrap(OperationRead, PhaseInput, ErrNilDatabase)
	}
	if !digestPattern.MatchString(bindingID) {
		return BindingRecord{}, wrap(OperationRead, PhaseInput, ErrBindingNotFound)
	}
	conn, err := c.store.db.Conn(ctx)
	if err != nil {
		return BindingRecord{}, wrap(OperationRead, PhaseConnect, err)
	}
	defer func() { _ = conn.Close() }()
	record, found, err := c.store.getBinding(ctx, conn, bindingID)
	if err != nil {
		return BindingRecord{}, err
	}
	if !found {
		return BindingRecord{}, wrap(OperationRead, PhaseRead, ErrBindingNotFound)
	}
	return record, nil
}

func getTypedArtifact[T any](
	ctx context.Context,
	store *sqlStore,
	name string,
	bindingID string,
	parse func([]byte) (types.Artifact[T], error),
) (types.Artifact[T], error) {
	var zero types.Artifact[T]
	if store == nil {
		return zero, wrap(OperationRead, PhaseInput, ErrNilDatabase)
	}
	if !digestPattern.MatchString(bindingID) {
		return zero, wrap(OperationRead, PhaseInput, ErrBindingNotFound)
	}
	conn, err := store.db.Conn(ctx)
	if err != nil {
		return zero, wrap(OperationRead, PhaseConnect, err)
	}
	defer func() { _ = conn.Close() }()

	record, found, err := store.getBinding(ctx, conn, bindingID)
	if err != nil {
		return zero, err
	}
	if !found {
		return zero, wrap(OperationRead, PhaseRead, ErrBindingNotFound)
	}
	if record.ArtifactName != name {
		return zero, wrap(OperationRead, PhaseRead, ErrArtifactTypeMismatch)
	}
	payload, err := store.readEvidence(ctx, conn, ObjectMeta{Digest: record.Digest, ArtifactName: name, ContractsVersion: storageFormatVersion})
	if err != nil {
		return zero, err
	}
	artifact, err := parse(payload)
	if err != nil {
		return zero, wrap(OperationRead, PhaseValidate, err)
	}
	return artifact, nil
}

func (s *sqlStore) readEvidence(ctx context.Context, conn *sql.Conn, meta ObjectMeta) ([]byte, error) {
	var size int64
	if err := s.queries.artifactEvidenceSizeGet(ctx, conn, artifactEvidenceSizeGetParams{digest: meta.Digest}).Scan(&size); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, wrap(OperationRead, PhaseRead, ErrNotFound)
		}
		return nil, wrap(OperationRead, PhaseRead, err)
	}
	meta.Size = size
	payload, err := s.objects.Get(ctx, meta)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, wrap(OperationRead, PhaseRead, err)
		}
		return nil, wrap(OperationRead, PhaseEvidence, err)
	}
	sum := sha256.Sum256(payload)
	if int64(len(payload)) != size || hex.EncodeToString(sum[:]) != meta.Digest {
		return nil, wrap(OperationRead, PhaseEvidence, ErrEvidenceCorrupt)
	}
	return payload, nil
}

// QueryFindingsSummary returns severity-and-verdict buckets for the Security Posture dashboard.
// It is narrower than the future compliance posture dashboard.
func (c *Client) QueryFindingsSummary(
	ctx context.Context,
	scopeIDs []string,
) ([]FindingsSummaryRow, error) {
	if c == nil || c.store == nil {
		return nil, wrap(OperationQuery, PhaseInput, ErrNilDatabase)
	}
	scope, err := scopeValue(scopeIDs)
	if err != nil {
		return nil, wrap(OperationQuery, PhaseInput, err)
	}
	conn, err := c.store.db.Conn(ctx)
	if err != nil {
		return nil, wrap(OperationQuery, PhaseConnect, err)
	}
	defer func() { _ = conn.Close() }()

	if err = c.store.prepareConnection(ctx, conn); err != nil {
		return nil, wrap(OperationQuery, PhaseConnect, err)
	}
	statement := "BEGIN"
	if c.store.dialect == dialectPostgres {
		statement = "BEGIN READ ONLY"
	}
	if _, err = conn.ExecContext(ctx, statement); err != nil {
		return nil, wrap(OperationQuery, PhaseBegin, err)
	}
	committed := false
	defer rollbackUnlessCommitted(ctx, conn, &committed)
	if c.store.dialect == dialectPostgres {
		if err = c.store.queries.scopeSet(
			ctx,
			conn,
			scopeSetParams{scopeIds: scope},
		); err != nil {
			return nil, wrap(OperationQuery, PhaseScope, err)
		}
	}

	rows, err := c.store.queries.findingsSummaryList(
		ctx,
		conn,
		findingsSummaryListParams{scopeIds: scope},
	)
	if err != nil {
		return nil, wrap(OperationQuery, PhaseRead, err)
	}
	result, err := scanFindingsSummary(rows)
	if err != nil {
		return nil, wrap(OperationQuery, PhaseRead, err)
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return nil, wrap(OperationQuery, PhaseCommit, err)
	}
	committed = true
	return result, nil
}

func scanFindingsSummary(rows *sql.Rows) (result []FindingsSummaryRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row FindingsSummaryRow
		if err := rows.Scan(
			&row.ScopeID,
			&row.SubjectID,
			&row.RunID,
			&row.LayerID,
			&row.Repository,
			&row.Severity,
			&row.Verdict,
			&row.FindingCount,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// FindingRow is one row of the open_findings and hardening_findings views.
//
// Both views project the same columns from the current_finding spine, which
// is what lets a dashboard swap "open" for "hardening" without reshaping its
// code. Nullable where the underlying artifact may not carry the field:
// disposition is optional, and ownership is absent until a corpus-registry
// has been ingested.
type FindingRow struct {
	ScopeID       string
	SubjectID     *string
	RunID         *string
	FindingID     string
	Title         *string
	Severity      *string
	Fingerprint   *string
	Validity      *string
	Resolution    *string
	Assurance     *string
	Family        string
	Ownership     *string
	BusinessUnit  *string
	Tree          *string
	IsBranchAudit *int64
}

// DistinctExposureRow is one row of the distinct_exposure view: one DISTINCT
// problem over owned HEAD audits, not one occurrence. Severity and business
// unit are examples, because a fingerprint collapses across both.
type DistinctExposureRow struct {
	ScopeID             string
	Fingerprint         string
	Occurrences         int64
	SeverityExample     *string
	BusinessUnitExample *string
	FirstSubject        *string
}

func scanFindings(rows *sql.Rows) (result []FindingRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row FindingRow
		if err := rows.Scan(
			&row.ScopeID, &row.SubjectID, &row.RunID, &row.FindingID,
			&row.Title, &row.Severity, &row.Fingerprint, &row.Validity,
			&row.Resolution, &row.Assurance, &row.Family, &row.Ownership,
			&row.BusinessUnit, &row.Tree, &row.IsBranchAudit,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func scanDistinctExposure(rows *sql.Rows) (result []DistinctExposureRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row DistinctExposureRow
		if err := rows.Scan(
			&row.ScopeID, &row.Fingerprint, &row.Occurrences,
			&row.SeverityExample, &row.BusinessUnitExample, &row.FirstSubject,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// scopedRead runs a scope-gated dashboard view inside a read-only
// transaction. One implementation for every view, so the scope contract is
// stated once: PostgreSQL fails CLOSED, returning zero rows rather than
// erroring when no scope is set, which reads as "no findings" when it means
// "misconfigured".
func scopedRead[T any](
	ctx context.Context,
	c *Client,
	scopeIDs []string,
	run func(context.Context, *sql.Conn, string) (*sql.Rows, error),
	scan func(*sql.Rows) ([]T, error),
) ([]T, error) {
	if c == nil || c.store == nil {
		return nil, wrap(OperationQuery, PhaseInput, ErrNilDatabase)
	}
	scope, err := scopeValue(scopeIDs)
	if err != nil {
		return nil, wrap(OperationQuery, PhaseInput, err)
	}
	conn, err := c.store.db.Conn(ctx)
	if err != nil {
		return nil, wrap(OperationQuery, PhaseConnect, err)
	}
	defer func() { _ = conn.Close() }()

	if err = c.store.prepareConnection(ctx, conn); err != nil {
		return nil, wrap(OperationQuery, PhaseConnect, err)
	}
	statement := "BEGIN"
	if c.store.dialect == dialectPostgres {
		statement = "BEGIN READ ONLY"
	}
	if _, err = conn.ExecContext(ctx, statement); err != nil {
		return nil, wrap(OperationQuery, PhaseBegin, err)
	}
	committed := false
	defer rollbackUnlessCommitted(ctx, conn, &committed)
	if c.store.dialect == dialectPostgres {
		if err = c.store.queries.scopeSet(ctx, conn, scopeSetParams{scopeIds: scope}); err != nil {
			return nil, wrap(OperationQuery, PhaseScope, err)
		}
	}
	rows, err := run(ctx, conn, scope)
	if err != nil {
		return nil, wrap(OperationQuery, PhaseRead, err)
	}
	result, err := scan(rows)
	if err != nil {
		return nil, wrap(OperationQuery, PhaseRead, err)
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return nil, wrap(OperationQuery, PhaseCommit, err)
	}
	committed = true
	return result, nil
}

// QueryOpenFindings returns open exposure: not affirmatively closed, not a
// false positive, not hardening. Spans BOTH finding families.
func (c *Client) QueryOpenFindings(ctx context.Context, scopeIDs []string) ([]FindingRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.openFindingsList(ctx, conn, openFindingsListParams{scopeIds: scope})
		}, scanFindings)
}

// QueryHardeningFindings returns posture debt, kept out of open exposure so
// the two are never blended.
func (c *Client) QueryHardeningFindings(ctx context.Context, scopeIDs []string) ([]FindingRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.hardeningFindingsList(ctx, conn, hardeningFindingsListParams{scopeIds: scope})
		}, scanFindings)
}

// QueryDistinctExposure returns Lens 2: distinct problems over owned HEAD
// audits, one row per fingerprint rather than one per occurrence.
func (c *Client) QueryDistinctExposure(ctx context.Context, scopeIDs []string) ([]DistinctExposureRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.distinctExposureList(ctx, conn, distinctExposureListParams{scopeIds: scope})
		}, scanDistinctExposure)
}

// CensusPopulationRow is one row of the census_population view: the
// DENOMINATOR, counted from ownership rather than from findings. A subject
// audited clean is still coverage; counting the denominator from findings
// drops it and overstates every percentage divided by it.
type CensusPopulationRow struct {
	ScopeID        string
	Tree           string
	Ownership      string
	BusinessUnit   string
	Subjects       int64
	BranchReaudits int64
	WithReport     int64
}

// CensusExposureRow is one row of the census_exposure view: every finding
// classified once into an exhaustive, mutually exclusive ExposureClass
// (false_positive | hardening | closed | open). Consumers FILTER this; they
// do not restate the disposition policy, which is where numbers drifted.
type CensusExposureRow struct {
	ScopeID              string
	Tree                 *string
	Ownership            *string
	BusinessUnit         *string
	IsBranchAudit        *int64
	Family               string
	Severity             *string
	ExposureClass        string
	Occurrences          int64
	DistinctFingerprints int64
}

func scanCensusPopulation(rows *sql.Rows) (result []CensusPopulationRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row CensusPopulationRow
		if err := rows.Scan(
			&row.ScopeID, &row.Tree, &row.Ownership, &row.BusinessUnit,
			&row.Subjects, &row.BranchReaudits, &row.WithReport,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func scanCensusExposure(rows *sql.Rows) (result []CensusExposureRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row CensusExposureRow
		if err := rows.Scan(
			&row.ScopeID, &row.Tree, &row.Ownership, &row.BusinessUnit,
			&row.IsBranchAudit, &row.Family, &row.Severity, &row.ExposureClass,
			&row.Occurrences, &row.DistinctFingerprints,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// QueryCensusPopulation returns the census denominator per tree, plus the
// coverage numerator (WithReport) and the branch-re-audit count that a
// coverage percentage must exclude.
func (c *Client) QueryCensusPopulation(ctx context.Context, scopeIDs []string) ([]CensusPopulationRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.censusPopulationList(ctx, conn, censusPopulationListParams{scopeIds: scope})
		}, scanCensusPopulation)
}

// QueryCensusExposure returns every finding classified once by exposure
// class, aggregated by tree, ownership, branch-audit, family and severity.
func (c *Client) QueryCensusExposure(ctx context.Context, scopeIDs []string) ([]CensusExposureRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.censusExposureList(ctx, conn, censusExposureListParams{scopeIds: scope})
		}, scanCensusExposure)
}

// ThreatRow is one modelled threat from the CURRENT register, with the owner
// of the subject it was modelled against.
type ThreatRow struct {
	ScopeID string
	// The identity. Never ThreatID: every model numbers its threats from T1,
	// so ThreatID alone collides across the whole model set.
	ThreatKey           string
	ThreatID            string
	Model               string
	SubjectID           *string
	Product             *string
	Statement           *string
	Surface             *string
	Asset               *string
	Impact              *string
	Likelihood          *string
	Status              *string
	Controls            *string
	Evidence            *string
	Linddun             *int64
	Score               *int64
	IsolationDimensions *string
	IsolationBoundaries *string
	Ownership           *string
	BusinessUnit        *string
	Tree                *string
	IsBranchAudit       *int64
}

// ThreatExposureRow aggregates modelled threats. Status is carried
// UNCOLLAPSED -- partially_mitigated is the largest bucket in practice, so
// folding it into mitigated overstates threat coverage more than any other
// choice here. Evidenced separates a threat backed by a finding from one that
// is only modelled: "unmitigated" and "unevidenced" are different claims.
type ThreatExposureRow struct {
	ScopeID      string
	Tree         *string
	Ownership    *string
	BusinessUnit *string
	Product      *string
	Impact       *string
	Likelihood   *string
	Status       *string
	Evidenced    int64
	Linddun      *int64
	Threats      int64
	Subjects     int64
	TopScore     *int64
}

// OperatorPrivilegeRow is the privilege one operator ASKS FOR, parsed from its
// shipped manifests. DECLARED state -- never a live cluster read. Each Flag*
// is 1 when that high-privilege pattern matched and 0 when it did not; never
// NULL, so a dashboard filter cannot silently drop a row.
type OperatorPrivilegeRow struct {
	ScopeID                     string
	SubjectID                   *string
	RunID                       *string
	Repo                        string
	Tier                        *string
	WorkloadCount               *int64
	PrivilegedOrHostWorkloads   *int64
	RbacRuleCount               *int64
	DistinctRuleTriples         *int64
	DistinctClusterTriples      *int64
	ClusterScopedRules          *int64
	WildcardRules               *int64
	NoSccRequestRecorded        *int64
	FlagSecretsAccess           int64
	FlagNodesAccess             int64
	FlagWildcardVerbs           int64
	FlagWildcardResources       int64
	FlagRbacWrite               int64
	FlagPodsExec                int64
	FlagEscalateBindImpersonate int64
	Ownership                   *string
	BusinessUnit                *string
	Tree                        *string
	IsBranchAudit               *int64
}

func scanThreats(rows *sql.Rows) (result []ThreatRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row ThreatRow
		if err := rows.Scan(
			&row.ScopeID, &row.ThreatKey, &row.ThreatID, &row.Model, &row.SubjectID,
			&row.Product, &row.Statement, &row.Surface, &row.Asset, &row.Impact,
			&row.Likelihood, &row.Status, &row.Controls, &row.Evidence, &row.Linddun,
			&row.Score, &row.IsolationDimensions, &row.IsolationBoundaries,
			&row.Ownership, &row.BusinessUnit, &row.Tree, &row.IsBranchAudit,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func scanThreatExposure(rows *sql.Rows) (result []ThreatExposureRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row ThreatExposureRow
		if err := rows.Scan(
			&row.ScopeID, &row.Tree, &row.Ownership, &row.BusinessUnit, &row.Product,
			&row.Impact, &row.Likelihood, &row.Status, &row.Evidenced, &row.Linddun,
			&row.Threats, &row.Subjects, &row.TopScore,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func scanOperatorPrivilege(rows *sql.Rows) (result []OperatorPrivilegeRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row OperatorPrivilegeRow
		if err := rows.Scan(
			&row.ScopeID, &row.SubjectID, &row.RunID, &row.Repo, &row.Tier,
			&row.WorkloadCount, &row.PrivilegedOrHostWorkloads, &row.RbacRuleCount,
			&row.DistinctRuleTriples, &row.DistinctClusterTriples,
			&row.ClusterScopedRules, &row.WildcardRules, &row.NoSccRequestRecorded,
			&row.FlagSecretsAccess, &row.FlagNodesAccess, &row.FlagWildcardVerbs,
			&row.FlagWildcardResources, &row.FlagRbacWrite, &row.FlagPodsExec,
			&row.FlagEscalateBindImpersonate,
			&row.Ownership, &row.BusinessUnit, &row.Tree, &row.IsBranchAudit,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// QueryThreatCurrent returns the threats of the CURRENT register, with owner.
func (c *Client) QueryThreatCurrent(ctx context.Context, scopeIDs []string) ([]ThreatRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.threatCurrentList(ctx, conn, threatCurrentListParams{scopeIds: scope})
		}, scanThreats)
}

// QueryThreatExposure returns threats aggregated by impact, likelihood and
// status, and whether each group is evidenced.
func (c *Client) QueryThreatExposure(ctx context.Context, scopeIDs []string) ([]ThreatExposureRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.threatExposureList(ctx, conn, threatExposureListParams{scopeIds: scope})
		}, scanThreatExposure)
}

// QueryOperatorPrivilege returns the privilege each operator asks for in its
// shipped manifests. Declared state, never a runtime grant.
func (c *Client) QueryOperatorPrivilege(ctx context.Context, scopeIDs []string) ([]OperatorPrivilegeRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.operatorPrivilegeList(ctx, conn, operatorPrivilegeListParams{scopeIds: scope})
		}, scanOperatorPrivilege)
}

// FindingTimelineRow is one finding identity with its full clock.
// DaysToResolve is nil while the finding is OPEN -- a mean taken over
// closed findings alone is censored and reads faster than reality.
// ClockInconsistent marks a resolution dated before the earliest report we
// still hold, where the duration is unknown rather than negative.
type FindingTimelineRow struct {
	ScopeID                  string
	Fingerprint              string
	FirstSeen                *string
	LastSeen                 *string
	Subjects                 int64
	FirstAdjudicated         *string
	ResolvedAt               *string
	RegressionAt             *string
	DaysToResolve            *float64
	ClockInconsistent        int64
	DaysAdjudicatedToResolve *float64
	RegressionDays           *float64
	RegressionStillOpen      *int64
	Events                   *int64
}

// ExposureTrendRow is findings opened and closed in one period, each
// identity counted once rather than once per re-audit.
type ExposureTrendRow struct {
	ScopeID string
	Period  string
	Opened  int64
	Closed  int64
	Net     int64
}

// FindingSLARow ages an open finding from FIRST OBSERVED. Still-open
// findings are included deliberately: the breaches are exactly the ones
// that never closed, so a closed-only view inverts the metric.
type FindingSLARow struct {
	ScopeID      string
	Fingerprint  string
	Severity     *string
	Ownership    *string
	BusinessUnit *string
	Tree         *string
	// Which policy judged this, and under which profile. Nil when no
	// sla-policy has been ingested for the scope.
	PolicyName  *string
	ProfileName *string
	// Which timestamp the POLICY says starts the clock.
	ClockStart     *string
	ClockStartedAt *string
	ResolvedAt     *string
	StillOpen      int64
	// Nil means the policy tracks this severity without clocking it, or
	// there is no policy. Breached is nil in both cases -- never false,
	// which would read as affirmatively within SLA.
	ResolveDays   *int64
	AgeDays       *float64
	Breached      *int64
	DaysToResolve *float64
}

// SLAThresholdRow is the deployment's own per-severity threshold, from the
// default profile of its sla-policy artifact.
type SLAThresholdRow struct {
	ScopeID         string
	PolicyName      string
	ProfileName     string
	ClockStart      string
	Severity        string
	ResolveDays     *int64
	AcknowledgeDays *int64
}

func scanFindingTimeline(rows *sql.Rows) (result []FindingTimelineRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row FindingTimelineRow
		if err := rows.Scan(
			&row.ScopeID, &row.Fingerprint, &row.FirstSeen, &row.LastSeen,
			&row.Subjects, &row.FirstAdjudicated, &row.ResolvedAt, &row.RegressionAt,
			&row.DaysToResolve, &row.ClockInconsistent, &row.DaysAdjudicatedToResolve,
			&row.RegressionDays, &row.RegressionStillOpen, &row.Events,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func scanExposureTrend(rows *sql.Rows) (result []ExposureTrendRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row ExposureTrendRow
		if err := rows.Scan(&row.ScopeID, &row.Period, &row.Opened,
			&row.Closed, &row.Net); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func scanFindingSLA(rows *sql.Rows) (result []FindingSLARow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row FindingSLARow
		if err := rows.Scan(
			&row.ScopeID, &row.Fingerprint, &row.Severity, &row.Ownership,
			&row.BusinessUnit, &row.Tree, &row.PolicyName, &row.ProfileName,
			&row.ClockStart, &row.ClockStartedAt, &row.ResolvedAt,
			&row.StillOpen, &row.ResolveDays, &row.AgeDays, &row.Breached,
			&row.DaysToResolve,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// QueryFindingTimeline returns each finding's clock: born, adjudicated,
// closed, and the durations between.
func (c *Client) QueryFindingTimeline(ctx context.Context, scopeIDs []string) ([]FindingTimelineRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.findingTimelineList(ctx, conn, findingTimelineListParams{scopeIds: scope})
		}, scanFindingTimeline)
}

// QueryExposureTrend returns findings opened and closed per period.
func (c *Client) QueryExposureTrend(ctx context.Context, scopeIDs []string) ([]ExposureTrendRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.exposureTrendList(ctx, conn, exposureTrendListParams{scopeIds: scope})
		}, scanExposureTrend)
}

// QueryFindingSLA returns the age of every finding against its SLA clock.
func (c *Client) QueryFindingSLA(ctx context.Context, scopeIDs []string) ([]FindingSLARow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.findingSlaList(ctx, conn, findingSlaListParams{scopeIds: scope})
		}, scanFindingSLA)
}

func scanSLAThreshold(rows *sql.Rows) (result []SLAThresholdRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row SLAThresholdRow
		if err := rows.Scan(
			&row.ScopeID, &row.PolicyName, &row.ProfileName, &row.ClockStart,
			&row.Severity, &row.ResolveDays, &row.AcknowledgeDays,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// QuerySLAThreshold returns the deployment's own per-severity thresholds
// from the default profile, so a consumer can show what the policy IS and
// not only who breached it.
func (c *Client) QuerySLAThreshold(ctx context.Context, scopeIDs []string) ([]SLAThresholdRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.slaThresholdList(ctx, conn, slaThresholdListParams{scopeIds: scope})
		}, scanSLAThreshold)
}

// PQCPostureRow is one subject's post-quantum readiness, with its owner.
// NotApplicable is a real bucket, not a gap: a repo with no
// key-establishment surface has nothing to migrate.
type PQCPostureRow struct {
	ScopeID         string
	SubjectID       *string
	ReadinessBucket *string
	Has2030Clock    *int64
	HNDLPriority    *int64
	// Whether the source assessment must be confirmed against a running
	// system before it can be relied on.
	RuntimeVerificationRequired *int64
	DominantProvenance          *string
	ClockItems                  *int64
	Ownership                   *string
	BusinessUnit                *string
	Tree                        *string
	IsBranchAudit               *int64
}

// PQCReadinessRollupRow aggregates readiness by bucket. Counts SUBJECTS,
// not assessments -- a repo re-assessed five times is one repo in a
// bucket, and counting assessments inflates the portfolio by rescan
// frequency.
type PQCReadinessRollupRow struct {
	ScopeID         string
	Tree            *string
	Ownership       *string
	BusinessUnit    *string
	ReadinessBucket *string
	Subjects        int64
	With2030Clock   *int64
	HNDLPriority    *int64
	ClockItems      *int64
}

func scanPQCPosture(rows *sql.Rows) (result []PQCPostureRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row PQCPostureRow
		if err := rows.Scan(
			&row.ScopeID, &row.SubjectID, &row.ReadinessBucket, &row.Has2030Clock,
			&row.HNDLPriority, &row.RuntimeVerificationRequired,
			&row.DominantProvenance, &row.ClockItems, &row.Ownership,
			&row.BusinessUnit, &row.Tree, &row.IsBranchAudit,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func scanPQCReadinessRollup(rows *sql.Rows) (result []PQCReadinessRollupRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row PQCReadinessRollupRow
		if err := rows.Scan(
			&row.ScopeID, &row.Tree, &row.Ownership, &row.BusinessUnit,
			&row.ReadinessBucket, &row.Subjects, &row.With2030Clock,
			&row.HNDLPriority, &row.ClockItems,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// QueryPQCPosture returns post-quantum readiness per subject.
func (c *Client) QueryPQCPosture(ctx context.Context, scopeIDs []string) ([]PQCPostureRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.pqcPostureList(ctx, conn, pqcPostureListParams{scopeIds: scope})
		}, scanPQCPosture)
}

// QueryPQCReadinessRollup returns readiness aggregated by bucket.
func (c *Client) QueryPQCReadinessRollup(ctx context.Context, scopeIDs []string) ([]PQCReadinessRollupRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.pqcReadinessRollupList(ctx, conn, pqcReadinessRollupListParams{scopeIds: scope})
		}, scanPQCReadinessRollup)
}

type AdvisoryExposureRow struct {
	ScopeID               string
	Advisory              *string
	Ecosystem             *string
	Module                *string
	FixedVersion          *string
	VulnerableRange       *string
	GeneratedAt           *string
	TiersExecuted         *string
	VulnerableSymbols     *string
	VulnerablePackages    *string
	AdvisorySources       *string
	FeatureDescription    *string
	HarnessVersion        *string
	Options               *string
	PortfolioGraphDB      *string
	PortfolioGraphVersion *string
	Repo                  *string
	Classification        *string
	Version               *string
	Direct                *int64
	Products              *string
	BinaryLinkedLibrary   *string
	BinaryStringScan      *string
	BinarySymbolScan      *string
	EvidenceLevel         *string
	FeaturePatternMatches *string
	Govulncheck           *string
	GovulncheckTrace      *string
	L1DependsOn           *string
	L1VersionInRange      *string
	L4PackageImported     *string
	L4PackagesFound       *string
	ManifestScan          *string
	ManifestVersion       *string
	NeedsManualTrace      *int64
	Notes                 *string
	SBOMScan              *string
	SBOMShippedVersion    *string
	SourceImportScan      *string
	SymbolUsageScan       *string
}

func scanAdvisoryExposure(rows *sql.Rows) (result []AdvisoryExposureRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row AdvisoryExposureRow
		if err := rows.Scan(
			&row.ScopeID, &row.Advisory, &row.Ecosystem, &row.Module,
			&row.FixedVersion, &row.VulnerableRange, &row.GeneratedAt, &row.TiersExecuted,
			&row.VulnerableSymbols, &row.VulnerablePackages, &row.AdvisorySources, &row.FeatureDescription,
			&row.HarnessVersion, &row.Options, &row.PortfolioGraphDB, &row.PortfolioGraphVersion,
			&row.Repo, &row.Classification, &row.Version, &row.Direct,
			&row.Products, &row.BinaryLinkedLibrary, &row.BinaryStringScan, &row.BinarySymbolScan,
			&row.EvidenceLevel, &row.FeaturePatternMatches, &row.Govulncheck, &row.GovulncheckTrace,
			&row.L1DependsOn, &row.L1VersionInRange, &row.L4PackageImported, &row.L4PackagesFound,
			&row.ManifestScan, &row.ManifestVersion, &row.NeedsManualTrace, &row.Notes,
			&row.SBOMScan, &row.SBOMShippedVersion, &row.SourceImportScan, &row.SymbolUsageScan,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// QueryAdvisoryExposure returns one row per repository an advisory reaches,
// carrying the evidence that explains HOW each classification was reached
// rather than the classification alone.
func (c *Client) QueryAdvisoryExposure(ctx context.Context, scopeIDs []string) ([]AdvisoryExposureRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.advisoryExposureList(ctx, conn, advisoryExposureListParams{scopeIds: scope})
		}, scanAdvisoryExposure)
}

type ValidationExposureRow struct {
	ScopeID           string
	TargetEnvironment *string
	Tree              *string
	Ownership         *string
	BusinessUnit      *string
	Product           *string
	ClaimedSeverity   *string
	Verdict           *string
	Attempted         *int64
	SkipReason        *string
	Findings          *int64
	Subjects          *int64
	DistinctClaims    *int64
}

func scanValidationExposure(rows *sql.Rows) (result []ValidationExposureRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row ValidationExposureRow
		if err := rows.Scan(
			&row.ScopeID, &row.TargetEnvironment, &row.Tree, &row.Ownership,
			&row.BusinessUnit, &row.Product, &row.ClaimedSeverity, &row.Verdict,
			&row.Attempted, &row.SkipReason, &row.Findings, &row.Subjects,
			&row.DistinctClaims,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// QueryValidationExposure aggregates what happened when claimed findings were
// ATTEMPTED live. verdict stays uncollapsed and attempted is derived rather
// than filtered: not_attempted dominates, so reporting only attempts would
// describe a fraction of the lane and read as though the rest were refuted.
func (c *Client) QueryValidationExposure(ctx context.Context, scopeIDs []string) ([]ValidationExposureRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.validationExposureList(ctx, conn, validationExposureListParams{scopeIds: scope})
		}, scanValidationExposure)
}

type ValidationCurrentRow struct {
	ScopeID            string
	SubjectID          *string
	RunID              *string
	TargetEnvironment  *string
	SourceID           string
	SourceFindingID    *string
	Title              *string
	ClaimedSeverity    *string
	Surface            *string
	Verdict            *string
	SkipReason         *string
	Technique          *string
	ObservedImpact     *string
	EvidenceGrade      *string
	GradeRationale     *string
	SoundnessFlag      *string
	SeverityValidation *string
	DeviationFromClaim *string
	RollbackPerformed  *int64
	ChainContext       *string
	NotAttemptedReason *string
	Ownership          *string
	BusinessUnit       *string
	Tree               *string
	Product            *string
	IsBranchAudit      *int64
}

func scanValidationCurrent(rows *sql.Rows) (result []ValidationCurrentRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row ValidationCurrentRow
		if err := rows.Scan(
			&row.ScopeID, &row.SubjectID, &row.RunID, &row.TargetEnvironment,
			&row.SourceID, &row.SourceFindingID, &row.Title, &row.ClaimedSeverity,
			&row.Surface, &row.Verdict, &row.SkipReason, &row.Technique,
			&row.ObservedImpact, &row.EvidenceGrade, &row.GradeRationale, &row.SoundnessFlag,
			&row.SeverityValidation, &row.DeviationFromClaim, &row.RollbackPerformed, &row.ChainContext,
			&row.NotAttemptedReason, &row.Ownership, &row.BusinessUnit, &row.Tree,
			&row.Product, &row.IsBranchAudit,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// QueryValidationCurrent returns one row per claimed finding at the grain the
// evidence lens works, with the owner of the subject it was validated
// against. QueryValidationExposure aggregates this.
func (c *Client) QueryValidationCurrent(ctx context.Context, scopeIDs []string) ([]ValidationCurrentRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.validationCurrentList(ctx, conn, validationCurrentListParams{scopeIds: scope})
		}, scanValidationCurrent)
}

type AttackCoverageRow struct {
	ScopeID      string
	Technique    string
	Source       string
	EvidenceTier int64
	Occurrences  int64
	Subjects     int64
}

func scanAttackCoverage(rows *sql.Rows) (result []AttackCoverageRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row AttackCoverageRow
		if err := rows.Scan(
			&row.ScopeID, &row.Technique, &row.Source, &row.EvidenceTier,
			&row.Occurrences, &row.Subjects,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// QueryAttackCoverage returns one row per ATT&CK technique per source, with
// evidence_tier separating a technique somebody WROTE DOWN from one somebody
// PROVED: 3 a chain confirmed end to end, 2 a chain attempted and not
// confirmed, 1 modelled only.
func (c *Client) QueryAttackCoverage(ctx context.Context, scopeIDs []string) ([]AttackCoverageRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.attackCoverageList(ctx, conn, attackCoverageListParams{scopeIds: scope})
		}, scanAttackCoverage)
}

type CompliancePostureRow struct {
	ScopeID        string
	SubjectID      *string
	RunID          *string
	Framework      string
	ControlID      string
	Title          *string
	Classification *string
	Verdict        *string
	VerdictSource  *string
	AssuranceTier  *int64
	CheckID        *string
	Reason         *string
	Narrative      *string
	Evidence       *string
	Override       *string
	NPassAgreement *string
	Ownership      *string
	BusinessUnit   *string
	Tree           *string
	Product        *string
	IsBranchAudit  *int64
}

func scanCompliancePosture(rows *sql.Rows) (result []CompliancePostureRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row CompliancePostureRow
		if err := rows.Scan(
			&row.ScopeID, &row.SubjectID, &row.RunID, &row.Framework,
			&row.ControlID, &row.Title, &row.Classification, &row.Verdict,
			&row.VerdictSource, &row.AssuranceTier, &row.CheckID, &row.Reason,
			&row.Narrative, &row.Evidence, &row.Override, &row.NPassAgreement,
			&row.Ownership, &row.BusinessUnit, &row.Tree, &row.Product,
			&row.IsBranchAudit,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// QueryCompliancePosture returns control verdicts of the current assessment.
// One row per control per framework, never a percentage, and verdict_source
// stays uncollapsed: satisfied-by-check and satisfied-by-human-override are
// different assurance claims.
func (c *Client) QueryCompliancePosture(ctx context.Context, scopeIDs []string) ([]CompliancePostureRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.compliancePostureList(ctx, conn, compliancePostureListParams{scopeIds: scope})
		}, scanCompliancePosture)
}

type PatternExposureRow struct {
	ScopeID              string
	Tree                 *string
	Ownership            *string
	BusinessUnit         *string
	Family               string
	CWE                  string
	Category             *string
	Severity             *string
	EffectiveSeverity    *string
	ExposureClass        string
	Occurrences          int64
	DistinctFingerprints int64
	Subjects             int64
}

func scanPatternExposure(rows *sql.Rows) (result []PatternExposureRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row PatternExposureRow
		if err := rows.Scan(
			&row.ScopeID, &row.Tree, &row.Ownership, &row.BusinessUnit,
			&row.Family, &row.CWE, &row.Category, &row.Severity,
			&row.EffectiveSeverity, &row.ExposureClass, &row.Occurrences, &row.DistinctFingerprints,
			&row.Subjects,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// QueryPatternExposure returns recurring weakness patterns, one row per CWE
// per cut. Fanned out of cwes[], so a finding declaring two weaknesses counts
// under both and Occurrences sums to more than the finding count.
func (c *Client) QueryPatternExposure(ctx context.Context, scopeIDs []string) ([]PatternExposureRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.patternExposureList(ctx, conn, patternExposureListParams{scopeIds: scope})
		}, scanPatternExposure)
}

type RemediationCurrentRow struct {
	ScopeID              string
	SubjectID            *string
	RunID                *string
	FindingRef           string
	Title                *string
	Severity             *string
	CWEs                 *string
	Locations            *string
	TriageConfidence     *float64
	ValidationVerdict    *string
	AuditReportPath      *string
	TriageReportPath     *string
	ValidationReportPath *string
	Ownership            *string
	BusinessUnit         *string
	Tree                 *string
	Product              *string
	IsBranchAudit        *int64
}

func scanRemediationCurrent(rows *sql.Rows) (result []RemediationCurrentRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row RemediationCurrentRow
		if err := rows.Scan(
			&row.ScopeID, &row.SubjectID, &row.RunID, &row.FindingRef,
			&row.Title, &row.Severity, &row.CWEs, &row.Locations,
			&row.TriageConfidence, &row.ValidationVerdict, &row.AuditReportPath, &row.TriageReportPath,
			&row.ValidationReportPath, &row.Ownership, &row.BusinessUnit, &row.Tree,
			&row.Product, &row.IsBranchAudit,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// QueryRemediationCurrent returns the findings each current remediation set
// out to fix. ValidationVerdict is the state AT REMEDIATION TIME, not now.
func (c *Client) QueryRemediationCurrent(ctx context.Context, scopeIDs []string) ([]RemediationCurrentRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.remediationCurrentList(ctx, conn, remediationCurrentListParams{scopeIds: scope})
		}, scanRemediationCurrent)
}

type VerificationCurrentRow struct {
	ScopeID                    string
	SubjectID                  *string
	RunID                      *string
	OriginalID                 string
	OriginalTitle              *string
	OriginalSeverity           *string
	Verdict                    *string
	Held                       int64
	Unattributed               *int64
	RemediationCommits         *string
	EvidenceExplanation        *string
	EvidenceFrameworkReference *string
	EvidenceOriginalCode       *string
	EvidencePatchedCode        *string
	DispositionRationale       *string
	ResidualRisk               *string
	ResidualSeverity           *string
	CrossRepo                  *string
	Ownership                  *string
	BusinessUnit               *string
	Tree                       *string
	Product                    *string
	IsBranchAudit              *int64
}

func scanVerificationCurrent(rows *sql.Rows) (result []VerificationCurrentRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row VerificationCurrentRow
		if err := rows.Scan(
			&row.ScopeID, &row.SubjectID, &row.RunID, &row.OriginalID,
			&row.OriginalTitle, &row.OriginalSeverity, &row.Verdict, &row.Held,
			&row.Unattributed, &row.RemediationCommits, &row.EvidenceExplanation, &row.EvidenceFrameworkReference,
			&row.EvidenceOriginalCode, &row.EvidencePatchedCode, &row.DispositionRationale, &row.ResidualRisk,
			&row.ResidualSeverity, &row.CrossRepo, &row.Ownership, &row.BusinessUnit,
			&row.Tree, &row.Product, &row.IsBranchAudit,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// QueryVerificationCurrent returns whether each fix held. Verdict keeps all
// seven contract values; Held is the narrow derived binary -- only resolved,
// because a false positive was never real and risk_accepted was never fixed.
func (c *Client) QueryVerificationCurrent(ctx context.Context, scopeIDs []string) ([]VerificationCurrentRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.verificationCurrentList(ctx, conn, verificationCurrentListParams{scopeIds: scope})
		}, scanVerificationCurrent)
}

type VerificationRegressionCurrentRow struct {
	ScopeID         string
	SubjectID       *string
	RunID           *string
	RegressionID    string
	Title           *string
	Severity        *string
	CWEs            *string
	CVSS            *string
	Locations       *string
	Description     *string
	Remediation     *string
	Evidence        *string
	AttackPattern   *string
	Category        *string
	IntroducedBy    *string
	RoutedID        *string
	Fingerprint     *string
	FingerprintAlgo *string
	Ownership       *string
	BusinessUnit    *string
	Tree            *string
	Product         *string
	IsBranchAudit   *int64
}

func scanVerificationRegressionCurrent(rows *sql.Rows) (result []VerificationRegressionCurrentRow, err error) {
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var row VerificationRegressionCurrentRow
		if err := rows.Scan(
			&row.ScopeID, &row.SubjectID, &row.RunID, &row.RegressionID,
			&row.Title, &row.Severity, &row.CWEs, &row.CVSS,
			&row.Locations, &row.Description, &row.Remediation, &row.Evidence,
			&row.AttackPattern, &row.Category, &row.IntroducedBy, &row.RoutedID,
			&row.Fingerprint, &row.FingerprintAlgo, &row.Ownership, &row.BusinessUnit,
			&row.Tree, &row.Product, &row.IsBranchAudit,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// QueryVerificationRegressionCurrent returns what each fix BROKE: new
// findings the remediation introduced, not restatements of the one it closed.
func (c *Client) QueryVerificationRegressionCurrent(ctx context.Context, scopeIDs []string) ([]VerificationRegressionCurrentRow, error) {
	return scopedRead(ctx, c, scopeIDs,
		func(ctx context.Context, conn *sql.Conn, scope string) (*sql.Rows, error) {
			return c.store.queries.verificationRegressionCurrentList(ctx, conn, verificationRegressionCurrentListParams{scopeIds: scope})
		}, scanVerificationRegressionCurrent)
}
