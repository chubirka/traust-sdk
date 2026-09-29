// Code generated from traust-contracts 65b16f8c72159970a3aec15121601739f59867b9 SQL queries. DO NOT EDIT.

package storage

import (
	"context"
	"database/sql"
)

type queries struct{ dialect dialect }

const adapterResultUpsertPostgres = "INSERT INTO traust_storage.adapter_result (\n    binding_id,\n    artifact_digest,\n    target,\n    scanned_at,\n    metadata,\n    findings,\n    summary,\n    focus_areas\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8\n)\nON CONFLICT (binding_id) DO NOTHING;"
const adapterResultUpsertSQLite = "INSERT INTO adapter_result (\n    binding_id,\n    artifact_digest,\n    target,\n    scanned_at,\n    metadata,\n    findings,\n    summary,\n    focus_areas\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type adapterResultUpsertParams struct {
	bindingId      string
	artifactDigest string
	target         string
	scannedAt      string
	metadata       string
	findings       string
	summary        *string
	focusAreas     *string
}

func (q queries) adapterResultUpsert(ctx context.Context, conn *sql.Conn, p adapterResultUpsertParams) error {
	statement := adapterResultUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = adapterResultUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.target, p.scannedAt, p.metadata, p.findings, p.summary, p.focusAreas)
	return err
}

const adrRegistryUpsertPostgres = "INSERT INTO traust_storage.adr_registry (\n    binding_id,\n    artifact_digest,\n    version,\n    note,\n    registers\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5\n)\nON CONFLICT (binding_id) DO NOTHING;"
const adrRegistryUpsertSQLite = "INSERT INTO adr_registry (\n    binding_id,\n    artifact_digest,\n    version,\n    note,\n    registers\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type adrRegistryUpsertParams struct {
	bindingId      string
	artifactDigest string
	version        int64
	note           *string
	registers      string
}

func (q queries) adrRegistryUpsert(ctx context.Context, conn *sql.Conn, p adrRegistryUpsertParams) error {
	statement := adrRegistryUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = adrRegistryUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.version, p.note, p.registers)
	return err
}

const advisoryExposureListPostgres = "SELECT scope_id,\n       advisory,\n       ecosystem,\n       module,\n       fixed_version,\n       vulnerable_range,\n       generated_at,\n       tiers_executed,\n       vulnerable_symbols,\n       vulnerable_packages,\n       advisory_sources,\n       feature_description,\n       harness_version,\n       options,\n       portfolio_graph_db,\n       portfolio_graph_version,\n       repo,\n       classification,\n       version,\n       direct,\n       products,\n       binary_linked_library,\n       binary_string_scan,\n       binary_symbol_scan,\n       evidence_level,\n       feature_pattern_matches,\n       govulncheck,\n       govulncheck_trace,\n       l1_depends_on,\n       l1_version_in_range,\n       l4_package_imported,\n       l4_packages_found,\n       manifest_scan,\n       manifest_version,\n       needs_manual_trace,\n       notes,\n       sbom_scan,\n       sbom_shipped_version,\n       source_import_scan,\n       symbol_usage_scan\nFROM traust_storage.advisory_exposure\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, advisory, classification, repo;"
const advisoryExposureListSQLite = "SELECT scope_id,\n       advisory,\n       ecosystem,\n       module,\n       fixed_version,\n       vulnerable_range,\n       generated_at,\n       tiers_executed,\n       vulnerable_symbols,\n       vulnerable_packages,\n       advisory_sources,\n       feature_description,\n       harness_version,\n       options,\n       portfolio_graph_db,\n       portfolio_graph_version,\n       repo,\n       classification,\n       version,\n       direct,\n       products,\n       binary_linked_library,\n       binary_string_scan,\n       binary_symbol_scan,\n       evidence_level,\n       feature_pattern_matches,\n       govulncheck,\n       govulncheck_trace,\n       l1_depends_on,\n       l1_version_in_range,\n       l4_package_imported,\n       l4_packages_found,\n       manifest_scan,\n       manifest_version,\n       needs_manual_trace,\n       notes,\n       sbom_scan,\n       sbom_shipped_version,\n       source_import_scan,\n       symbol_usage_scan\nFROM advisory_exposure\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, advisory, classification, repo;"

type advisoryExposureListParams struct {
	scopeIds string
}

func (q queries) advisoryExposureList(ctx context.Context, conn *sql.Conn, p advisoryExposureListParams) (*sql.Rows, error) {
	statement := advisoryExposureListSQLite
	if q.dialect == dialectPostgres {
		statement = advisoryExposureListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const artifactLockPostgres = "-- Serialize a digest: first eight SHA-256 bytes interpreted as signed big-endian int64.\nSELECT pg_advisory_xact_lock($1);"
const artifactLockSQLite = ""

type artifactLockParams struct {
	lockKey int64
}

func (q queries) artifactLock(ctx context.Context, conn *sql.Conn, p artifactLockParams) error {
	statement := artifactLockSQLite
	if q.dialect == dialectPostgres {
		statement = artifactLockPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.lockKey)
	return err
}

const artifactBindingGetPostgres = "SELECT artifact_digest,\n       artifact_name,\n       scope_id,\n       subject_id,\n       run_id,\n       layer_id,\n       supersedes_binding_id,\n       bound_at\nFROM traust_storage.artifact_binding\nWHERE binding_id = $1;"
const artifactBindingGetSQLite = "SELECT artifact_digest,\n       artifact_name,\n       scope_id,\n       subject_id,\n       run_id,\n       layer_id,\n       supersedes_binding_id,\n       bound_at\nFROM artifact_binding\nWHERE binding_id = ?;"

type artifactBindingGetParams struct {
	bindingId string
}

func (q queries) artifactBindingGet(ctx context.Context, conn *sql.Conn, p artifactBindingGetParams) *sql.Row {
	statement := artifactBindingGetSQLite
	if q.dialect == dialectPostgres {
		statement = artifactBindingGetPostgres
	}
	return conn.QueryRowContext(ctx, statement, p.bindingId)
}

const artifactBindingUpsertPostgres = "INSERT INTO traust_storage.artifact_binding (\n    binding_id,\n    artifact_digest,\n    artifact_name,\n    scope_id,\n    subject_id,\n    run_id,\n    layer_id,\n    supersedes_binding_id,\n    bound_at\n)\nVALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9\n)\nON CONFLICT (binding_id) DO NOTHING;"
const artifactBindingUpsertSQLite = "INSERT INTO artifact_binding (\n    binding_id,\n    artifact_digest,\n    artifact_name,\n    scope_id,\n    subject_id,\n    run_id,\n    layer_id,\n    supersedes_binding_id,\n    bound_at\n)\nVALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type artifactBindingUpsertParams struct {
	bindingId           string
	artifactDigest      string
	artifactName        string
	scopeId             string
	subjectId           *string
	runId               *string
	layerId             *string
	supersedesBindingId *string
	boundAt             string
}

func (q queries) artifactBindingUpsert(ctx context.Context, conn *sql.Conn, p artifactBindingUpsertParams) error {
	statement := artifactBindingUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = artifactBindingUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.artifactName, p.scopeId, p.subjectId, p.runId, p.layerId, p.supersedesBindingId, p.boundAt)
	return err
}

const artifactEvidenceUpsertPostgres = "INSERT INTO traust_storage.artifact_evidence (\n    digest,\n    byte_size,\n    first_ingested_at\n)\nVALUES (\n    $1,\n    $2,\n    $3\n)\nON CONFLICT (digest) DO NOTHING;"
const artifactEvidenceUpsertSQLite = "INSERT INTO artifact_evidence (\n    digest,\n    byte_size,\n    first_ingested_at\n)\nVALUES (\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (digest) DO NOTHING;"

type artifactEvidenceUpsertParams struct {
	digest          string
	byteSize        int64
	firstIngestedAt string
}

func (q queries) artifactEvidenceUpsert(ctx context.Context, conn *sql.Conn, p artifactEvidenceUpsertParams) error {
	statement := artifactEvidenceUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = artifactEvidenceUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.digest, p.byteSize, p.firstIngestedAt)
	return err
}

const attackChainUpsertPostgres = "INSERT INTO traust_storage.attack_chain (\n    binding_id,\n    artifact_digest,\n    chain_id,\n    name,\n    entry_point,\n    terminal_asset,\n    mitre_attack_refs,\n    steps,\n    verdict,\n    narrative\n)\nVALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10\n)\nON CONFLICT (binding_id, chain_id) DO NOTHING;"
const attackChainUpsertSQLite = "INSERT INTO attack_chain (\n    binding_id,\n    artifact_digest,\n    chain_id,\n    name,\n    entry_point,\n    terminal_asset,\n    mitre_attack_refs,\n    steps,\n    verdict,\n    narrative\n)\nVALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id, chain_id) DO NOTHING;"

type attackChainUpsertParams struct {
	bindingId       string
	artifactDigest  string
	chainId         string
	name            *string
	entryPoint      *string
	terminalAsset   *string
	mitreAttackRefs *string
	steps           *string
	verdict         *string
	narrative       *string
}

func (q queries) attackChainUpsert(ctx context.Context, conn *sql.Conn, p attackChainUpsertParams) error {
	statement := attackChainUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = attackChainUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.chainId, p.name, p.entryPoint, p.terminalAsset, p.mitreAttackRefs, p.steps, p.verdict, p.narrative)
	return err
}

const attackCoverageListPostgres = "SELECT scope_id,\n       technique,\n       source,\n       evidence_tier,\n       occurrences,\n       subjects\nFROM traust_storage.attack_coverage\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, technique, evidence_tier DESC;"
const attackCoverageListSQLite = "SELECT scope_id,\n       technique,\n       source,\n       evidence_tier,\n       occurrences,\n       subjects\nFROM attack_coverage\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, technique, evidence_tier DESC;"

type attackCoverageListParams struct {
	scopeIds string
}

func (q queries) attackCoverageList(ctx context.Context, conn *sql.Conn, p attackCoverageListParams) (*sql.Rows, error) {
	statement := attackCoverageListSQLite
	if q.dialect == dialectPostgres {
		statement = attackCoverageListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const attackMappingUpsertPostgres = "INSERT INTO traust_storage.attack_mapping (\n    binding_id,\n    artifact_digest,\n    mapping_version,\n    attack_version,\n    source,\n    documentation,\n    schema,\n    attribution,\n    capability_map,\n    category_map\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10\n)\nON CONFLICT (binding_id) DO NOTHING;"
const attackMappingUpsertSQLite = "INSERT INTO attack_mapping (\n    binding_id,\n    artifact_digest,\n    mapping_version,\n    attack_version,\n    source,\n    documentation,\n    schema,\n    attribution,\n    capability_map,\n    category_map\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type attackMappingUpsertParams struct {
	bindingId      string
	artifactDigest string
	mappingVersion string
	attackVersion  string
	source         string
	documentation  *string
	schema         *string
	attribution    string
	capabilityMap  string
	categoryMap    string
}

func (q queries) attackMappingUpsert(ctx context.Context, conn *sql.Conn, p attackMappingUpsertParams) error {
	statement := attackMappingUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = attackMappingUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.mappingVersion, p.attackVersion, p.source, p.documentation, p.schema, p.attribution, p.capabilityMap, p.categoryMap)
	return err
}

const benchmarkTargetUpsertPostgres = "INSERT INTO traust_storage.benchmark_target (\n    binding_id,\n    artifact_digest,\n    version,\n    updated,\n    targets\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5\n)\nON CONFLICT (binding_id) DO NOTHING;"
const benchmarkTargetUpsertSQLite = "INSERT INTO benchmark_target (\n    binding_id,\n    artifact_digest,\n    version,\n    updated,\n    targets\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type benchmarkTargetUpsertParams struct {
	bindingId      string
	artifactDigest string
	version        int64
	updated        string
	targets        string
}

func (q queries) benchmarkTargetUpsert(ctx context.Context, conn *sql.Conn, p benchmarkTargetUpsertParams) error {
	statement := benchmarkTargetUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = benchmarkTargetUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.version, p.updated, p.targets)
	return err
}

const censusExposureListPostgres = "SELECT scope_id,\n       tree,\n       ownership,\n       business_unit,\n       is_branch_audit,\n       family,\n       severity,\n       exposure_class,\n       occurrences,\n       distinct_fingerprints\nFROM traust_storage.census_exposure\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, tree, ownership, business_unit, is_branch_audit,\n         family, severity, exposure_class;"
const censusExposureListSQLite = "SELECT scope_id,\n       tree,\n       ownership,\n       business_unit,\n       is_branch_audit,\n       family,\n       severity,\n       exposure_class,\n       occurrences,\n       distinct_fingerprints\nFROM census_exposure\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, tree, ownership, business_unit, is_branch_audit,\n         family, severity, exposure_class;"

type censusExposureListParams struct {
	scopeIds string
}

func (q queries) censusExposureList(ctx context.Context, conn *sql.Conn, p censusExposureListParams) (*sql.Rows, error) {
	statement := censusExposureListSQLite
	if q.dialect == dialectPostgres {
		statement = censusExposureListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const censusPopulationListPostgres = "SELECT scope_id,\n       tree,\n       ownership,\n       business_unit,\n       subjects,\n       branch_reaudits,\n       with_report\nFROM traust_storage.census_population\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, tree, ownership, business_unit;"
const censusPopulationListSQLite = "SELECT scope_id,\n       tree,\n       ownership,\n       business_unit,\n       subjects,\n       branch_reaudits,\n       with_report\nFROM census_population\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, tree, ownership, business_unit;"

type censusPopulationListParams struct {
	scopeIds string
}

func (q queries) censusPopulationList(ctx context.Context, conn *sql.Conn, p censusPopulationListParams) (*sql.Rows, error) {
	statement := censusPopulationListSQLite
	if q.dialect == dialectPostgres {
		statement = censusPopulationListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const cloudConfigAuditUpsertPostgres = "INSERT INTO traust_storage.cloud_config_audit (\n    binding_id,\n    artifact_digest,\n    title,\n    metadata,\n    summary,\n    findings,\n    gaps\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7\n)\nON CONFLICT (binding_id) DO NOTHING;"
const cloudConfigAuditUpsertSQLite = "INSERT INTO cloud_config_audit (\n    binding_id,\n    artifact_digest,\n    title,\n    metadata,\n    summary,\n    findings,\n    gaps\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type cloudConfigAuditUpsertParams struct {
	bindingId      string
	artifactDigest string
	title          string
	metadata       string
	summary        string
	findings       string
	gaps           *string
}

func (q queries) cloudConfigAuditUpsert(ctx context.Context, conn *sql.Conn, p cloudConfigAuditUpsertParams) error {
	statement := cloudConfigAuditUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = cloudConfigAuditUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.title, p.metadata, p.summary, p.findings, p.gaps)
	return err
}

const cloudConfigFindingUpsertPostgres = "INSERT INTO traust_storage.cloud_config_finding (\n    binding_id,\n    artifact_digest,\n    finding_id,\n    title,\n    severity,\n    fingerprint,\n    validation_status,\n    check_id,\n    framework,\n    provider,\n    status,\n    scanner_severity,\n    validity,\n    resolution,\n    assurance,\n    last_updated,\n    conflict,\n    fp_overridden,\n    fp_reassertion_blocked,\n    refuted_awaiting_signoff,\n    severity_override,\n    rationale,\n    remediation,\n    cwe,\n    control_refs,\n    locations,\n    fact_ids,\n    external_correlation,\n    effective_severity,\n    fingerprint_algo,\n    isolation_boundary,\n    isolation_dimensions\n)\nVALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12,\n    $13,\n    $14,\n    $15,\n    $16,\n    $17,\n    $18,\n    $19,\n    $20,\n    $21,\n    $22,\n    $23,\n    $24,\n    $25,\n    $26,\n    $27,\n    $28,\n    $29,\n    $30,\n    $31,\n    $32\n)\nON CONFLICT (binding_id, finding_id) DO NOTHING;"
const cloudConfigFindingUpsertSQLite = "INSERT INTO cloud_config_finding (\n    binding_id,\n    artifact_digest,\n    finding_id,\n    title,\n    severity,\n    fingerprint,\n    validation_status,\n    check_id,\n    framework,\n    provider,\n    status,\n    scanner_severity,\n    validity,\n    resolution,\n    assurance,\n    last_updated,\n    conflict,\n    fp_overridden,\n    fp_reassertion_blocked,\n    refuted_awaiting_signoff,\n    severity_override,\n    rationale,\n    remediation,\n    cwe,\n    control_refs,\n    locations,\n    fact_ids,\n    external_correlation,\n    effective_severity,\n    fingerprint_algo,\n    isolation_boundary,\n    isolation_dimensions\n)\nVALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id, finding_id) DO NOTHING;"

type cloudConfigFindingUpsertParams struct {
	bindingId              string
	artifactDigest         string
	findingId              string
	title                  *string
	severity               *string
	fingerprint            *string
	validationStatus       *string
	checkId                *string
	framework              *string
	provider               *string
	status                 *string
	scannerSeverity        *string
	validity               *string
	resolution             *string
	assurance              *string
	lastUpdated            *string
	conflict               *int64
	fpOverridden           *int64
	fpReassertionBlocked   *int64
	refutedAwaitingSignoff *int64
	severityOverride       *string
	rationale              *string
	remediation            *string
	cwe                    *string
	controlRefs            *string
	locations              *string
	factIds                *string
	externalCorrelation    *string
	effectiveSeverity      *string
	fingerprintAlgo        *string
	isolationBoundary      *string
	isolationDimensions    *string
}

func (q queries) cloudConfigFindingUpsert(ctx context.Context, conn *sql.Conn, p cloudConfigFindingUpsertParams) error {
	statement := cloudConfigFindingUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = cloudConfigFindingUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.findingId, p.title, p.severity, p.fingerprint, p.validationStatus, p.checkId, p.framework, p.provider, p.status, p.scannerSeverity, p.validity, p.resolution, p.assurance, p.lastUpdated, p.conflict, p.fpOverridden, p.fpReassertionBlocked, p.refutedAwaitingSignoff, p.severityOverride, p.rationale, p.remediation, p.cwe, p.controlRefs, p.locations, p.factIds, p.externalCorrelation, p.effectiveSeverity, p.fingerprintAlgo, p.isolationBoundary, p.isolationDimensions)
	return err
}

const cloudConfigFindingsCurrentUpsertPostgres = "INSERT INTO traust_storage.cloud_config_findings_current (\n    binding_id,\n    artifact_digest,\n    title,\n    metadata,\n    summary,\n    findings,\n    gaps,\n    disposition_summary\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8\n)\nON CONFLICT (binding_id) DO NOTHING;"
const cloudConfigFindingsCurrentUpsertSQLite = "INSERT INTO cloud_config_findings_current (\n    binding_id,\n    artifact_digest,\n    title,\n    metadata,\n    summary,\n    findings,\n    gaps,\n    disposition_summary\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type cloudConfigFindingsCurrentUpsertParams struct {
	bindingId          string
	artifactDigest     string
	title              string
	metadata           string
	summary            string
	findings           string
	gaps               *string
	dispositionSummary string
}

func (q queries) cloudConfigFindingsCurrentUpsert(ctx context.Context, conn *sql.Conn, p cloudConfigFindingsCurrentUpsertParams) error {
	statement := cloudConfigFindingsCurrentUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = cloudConfigFindingsCurrentUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.title, p.metadata, p.summary, p.findings, p.gaps, p.dispositionSummary)
	return err
}

const complianceAssessmentUpsertPostgres = "INSERT INTO traust_storage.compliance_assessment (\n    binding_id,\n    artifact_digest,\n    metadata,\n    coverage,\n    results\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5\n)\nON CONFLICT (binding_id) DO NOTHING;"
const complianceAssessmentUpsertSQLite = "INSERT INTO compliance_assessment (\n    binding_id,\n    artifact_digest,\n    metadata,\n    coverage,\n    results\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type complianceAssessmentUpsertParams struct {
	bindingId      string
	artifactDigest string
	metadata       string
	coverage       string
	results        string
}

func (q queries) complianceAssessmentUpsert(ctx context.Context, conn *sql.Conn, p complianceAssessmentUpsertParams) error {
	statement := complianceAssessmentUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = complianceAssessmentUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.metadata, p.coverage, p.results)
	return err
}

const complianceMappingUpsertPostgres = "INSERT INTO traust_storage.compliance_mapping (\n    binding_id,\n    artifact_digest,\n    version,\n    note,\n    controls,\n    checks\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6\n)\nON CONFLICT (binding_id) DO NOTHING;"
const complianceMappingUpsertSQLite = "INSERT INTO compliance_mapping (\n    binding_id,\n    artifact_digest,\n    version,\n    note,\n    controls,\n    checks\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type complianceMappingUpsertParams struct {
	bindingId      string
	artifactDigest string
	version        int64
	note           *string
	controls       string
	checks         string
}

func (q queries) complianceMappingUpsert(ctx context.Context, conn *sql.Conn, p complianceMappingUpsertParams) error {
	statement := complianceMappingUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = complianceMappingUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.version, p.note, p.controls, p.checks)
	return err
}

const compliancePostureListPostgres = "SELECT scope_id,\n       subject_id,\n       run_id,\n       framework,\n       control_id,\n       title,\n       classification,\n       verdict,\n       verdict_source,\n       assurance_tier,\n       check_id,\n       reason,\n       narrative,\n       evidence,\n       override,\n       n_pass_agreement,\n       ownership,\n       business_unit,\n       tree,\n       product,\n       is_branch_audit\nFROM traust_storage.compliance_posture\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, framework, control_id, subject_id;"
const compliancePostureListSQLite = "SELECT scope_id,\n       subject_id,\n       run_id,\n       framework,\n       control_id,\n       title,\n       classification,\n       verdict,\n       verdict_source,\n       assurance_tier,\n       check_id,\n       reason,\n       narrative,\n       evidence,\n       override,\n       n_pass_agreement,\n       ownership,\n       business_unit,\n       tree,\n       product,\n       is_branch_audit\nFROM compliance_posture\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, framework, control_id, subject_id;"

type compliancePostureListParams struct {
	scopeIds string
}

func (q queries) compliancePostureList(ctx context.Context, conn *sql.Conn, p compliancePostureListParams) (*sql.Rows, error) {
	statement := compliancePostureListSQLite
	if q.dialect == dialectPostgres {
		statement = compliancePostureListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const complianceResultUpsertPostgres = "INSERT INTO traust_storage.compliance_result (\n    binding_id,\n    artifact_digest,\n    framework,\n    control_id,\n    title,\n    classification,\n    verdict,\n    verdict_source,\n    check_id,\n    reason,\n    narrative,\n    evidence,\n    override,\n    n_pass_agreement\n)\nVALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12,\n    $13,\n    $14\n)\nON CONFLICT (binding_id, framework, control_id) DO NOTHING;"
const complianceResultUpsertSQLite = "INSERT INTO compliance_result (\n    binding_id,\n    artifact_digest,\n    framework,\n    control_id,\n    title,\n    classification,\n    verdict,\n    verdict_source,\n    check_id,\n    reason,\n    narrative,\n    evidence,\n    override,\n    n_pass_agreement\n)\nVALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id, framework, control_id) DO NOTHING;"

type complianceResultUpsertParams struct {
	bindingId      string
	artifactDigest string
	framework      string
	controlId      string
	title          *string
	classification *string
	verdict        *string
	verdictSource  *string
	checkId        *string
	reason         *string
	narrative      *string
	evidence       *string
	override       *string
	nPassAgreement *string
}

func (q queries) complianceResultUpsert(ctx context.Context, conn *sql.Conn, p complianceResultUpsertParams) error {
	statement := complianceResultUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = complianceResultUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.framework, p.controlId, p.title, p.classification, p.verdict, p.verdictSource, p.checkId, p.reason, p.narrative, p.evidence, p.override, p.nPassAgreement)
	return err
}

const complianceScopeUpsertPostgres = "INSERT INTO traust_storage.compliance_scope (\n    binding_id,\n    artifact_digest,\n    version,\n    updated,\n    boundaries\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5\n)\nON CONFLICT (binding_id) DO NOTHING;"
const complianceScopeUpsertSQLite = "INSERT INTO compliance_scope (\n    binding_id,\n    artifact_digest,\n    version,\n    updated,\n    boundaries\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type complianceScopeUpsertParams struct {
	bindingId      string
	artifactDigest string
	version        int64
	updated        string
	boundaries     string
}

func (q queries) complianceScopeUpsert(ctx context.Context, conn *sql.Conn, p complianceScopeUpsertParams) error {
	statement := complianceScopeUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = complianceScopeUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.version, p.updated, p.boundaries)
	return err
}

const distinctExposureListPostgres = "SELECT scope_id,\n       fingerprint,\n       occurrences,\n       severity_example,\n       business_unit_example,\n       first_subject\nFROM traust_storage.distinct_exposure\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, fingerprint;"
const distinctExposureListSQLite = "SELECT scope_id,\n       fingerprint,\n       occurrences,\n       severity_example,\n       business_unit_example,\n       first_subject\nFROM distinct_exposure\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, fingerprint;"

type distinctExposureListParams struct {
	scopeIds string
}

func (q queries) distinctExposureList(ctx context.Context, conn *sql.Conn, p distinctExposureListParams) (*sql.Rows, error) {
	statement := distinctExposureListSQLite
	if q.dialect == dialectPostgres {
		statement = distinctExposureListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const docVarianceUpsertPostgres = "INSERT INTO traust_storage.doc_variance (\n    binding_id,\n    artifact_digest,\n    metadata,\n    records\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4\n)\nON CONFLICT (binding_id) DO NOTHING;"
const docVarianceUpsertSQLite = "INSERT INTO doc_variance (\n    binding_id,\n    artifact_digest,\n    metadata,\n    records\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type docVarianceUpsertParams struct {
	bindingId      string
	artifactDigest string
	metadata       string
	records        string
}

func (q queries) docVarianceUpsert(ctx context.Context, conn *sql.Conn, p docVarianceUpsertParams) error {
	statement := docVarianceUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = docVarianceUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.metadata, p.records)
	return err
}

const exposureTrendListPostgres = "SELECT scope_id,\n       period,\n       opened,\n       closed,\n       net\nFROM traust_storage.exposure_trend\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, period;"
const exposureTrendListSQLite = "SELECT scope_id,\n       period,\n       opened,\n       closed,\n       net\nFROM exposure_trend\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, period;"

type exposureTrendListParams struct {
	scopeIds string
}

func (q queries) exposureTrendList(ctx context.Context, conn *sql.Conn, p exposureTrendListParams) (*sql.Rows, error) {
	statement := exposureTrendListSQLite
	if q.dialect == dialectPostgres {
		statement = exposureTrendListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const findingUpsertPostgres = "INSERT INTO traust_storage.finding (\n    binding_id,\n    artifact_digest,\n    finding_id,\n    target,\n    scanned_at,\n    title,\n    severity,\n    description,\n    category,\n    file,\n    line,\n    cwe,\n    recommendation,\n    confidence\n)\nVALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12,\n    $13,\n    $14\n)\nON CONFLICT (binding_id, finding_id) DO NOTHING;"
const findingUpsertSQLite = "INSERT INTO finding (\n    binding_id,\n    artifact_digest,\n    finding_id,\n    target,\n    scanned_at,\n    title,\n    severity,\n    description,\n    category,\n    file,\n    line,\n    cwe,\n    recommendation,\n    confidence\n)\nVALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id, finding_id) DO NOTHING;"

type findingUpsertParams struct {
	bindingId      string
	artifactDigest string
	findingId      string
	target         string
	scannedAt      string
	title          string
	severity       string
	description    string
	category       *string
	file           string
	line           *int64
	cwe            *string
	recommendation string
	confidence     float64
}

func (q queries) findingUpsert(ctx context.Context, conn *sql.Conn, p findingUpsertParams) error {
	statement := findingUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = findingUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.findingId, p.target, p.scannedAt, p.title, p.severity, p.description, p.category, p.file, p.line, p.cwe, p.recommendation, p.confidence)
	return err
}

const findingSlaListPostgres = "SELECT scope_id,\n       fingerprint,\n       severity,\n       ownership,\n       business_unit,\n       tree,\n       policy_name,\n       profile_name,\n       clock_start,\n       clock_started_at,\n       resolved_at,\n       still_open,\n       resolve_days,\n       age_days,\n       breached,\n       days_to_resolve\nFROM traust_storage.finding_sla\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, age_days DESC;"
const findingSlaListSQLite = "SELECT scope_id,\n       fingerprint,\n       severity,\n       ownership,\n       business_unit,\n       tree,\n       policy_name,\n       profile_name,\n       clock_start,\n       clock_started_at,\n       resolved_at,\n       still_open,\n       resolve_days,\n       age_days,\n       breached,\n       days_to_resolve\nFROM finding_sla\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, age_days DESC;"

type findingSlaListParams struct {
	scopeIds string
}

func (q queries) findingSlaList(ctx context.Context, conn *sql.Conn, p findingSlaListParams) (*sql.Rows, error) {
	statement := findingSlaListSQLite
	if q.dialect == dialectPostgres {
		statement = findingSlaListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const findingTimelineListPostgres = "SELECT scope_id,\n       fingerprint,\n       first_seen,\n       last_seen,\n       subjects,\n       first_adjudicated,\n       first_routed_or_filed,\n       resolved_at,\n       regression_at,\n       days_to_resolve,\n       clock_inconsistent,\n       days_adjudicated_to_resolve,\n       regression_days,\n       regression_still_open,\n       events\nFROM traust_storage.finding_timeline\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, fingerprint;"
const findingTimelineListSQLite = "SELECT scope_id,\n       fingerprint,\n       first_seen,\n       last_seen,\n       subjects,\n       first_adjudicated,\n       first_routed_or_filed,\n       resolved_at,\n       regression_at,\n       days_to_resolve,\n       clock_inconsistent,\n       days_adjudicated_to_resolve,\n       regression_days,\n       regression_still_open,\n       events\nFROM finding_timeline\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, fingerprint;"

type findingTimelineListParams struct {
	scopeIds string
}

func (q queries) findingTimelineList(ctx context.Context, conn *sql.Conn, p findingTimelineListParams) (*sql.Rows, error) {
	statement := findingTimelineListSQLite
	if q.dialect == dialectPostgres {
		statement = findingTimelineListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const findingsSummaryListPostgres = "SELECT scope_id,\n       subject_id,\n       run_id,\n       layer_id,\n       repo,\n       severity,\n       verdict,\n       finding_count\nFROM traust_storage.findings_summary\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, subject_id, run_id, layer_id, repo, severity, verdict;"
const findingsSummaryListSQLite = "SELECT scope_id,\n       subject_id,\n       run_id,\n       layer_id,\n       repo,\n       severity,\n       verdict,\n       finding_count\nFROM findings_summary\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, subject_id, run_id, layer_id, repo, severity, verdict;"

type findingsSummaryListParams struct {
	scopeIds string
}

func (q queries) findingsSummaryList(ctx context.Context, conn *sql.Conn, p findingsSummaryListParams) (*sql.Rows, error) {
	statement := findingsSummaryListSQLite
	if q.dialect == dialectPostgres {
		statement = findingsSummaryListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const fleetFixUpsertPostgres = "INSERT INTO traust_storage.fleet_fix (\n    binding_id,\n    artifact_digest,\n    id,\n    pattern_ref,\n    description,\n    matcher,\n    resolver,\n    rewrite,\n    guards,\n    tests\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10\n)\nON CONFLICT (binding_id) DO NOTHING;"
const fleetFixUpsertSQLite = "INSERT INTO fleet_fix (\n    binding_id,\n    artifact_digest,\n    id,\n    pattern_ref,\n    description,\n    matcher,\n    resolver,\n    rewrite,\n    guards,\n    tests\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type fleetFixUpsertParams struct {
	bindingId      string
	artifactDigest string
	id             string
	patternRef     string
	description    string
	matcher        string
	resolver       *string
	rewrite        string
	guards         string
	tests          string
}

func (q queries) fleetFixUpsert(ctx context.Context, conn *sql.Conn, p fleetFixUpsertParams) error {
	statement := fleetFixUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = fleetFixUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.id, p.patternRef, p.description, p.matcher, p.resolver, p.rewrite, p.guards, p.tests)
	return err
}

const hardeningFindingsListPostgres = "SELECT scope_id,\n       subject_id,\n       run_id,\n       finding_id,\n       title,\n       severity,\n       fingerprint,\n       validity,\n       resolution,\n       assurance,\n       family,\n       ownership,\n       business_unit,\n       tree,\n       is_branch_audit\nFROM traust_storage.hardening_findings\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, subject_id, run_id, finding_id, title;"
const hardeningFindingsListSQLite = "SELECT scope_id,\n       subject_id,\n       run_id,\n       finding_id,\n       title,\n       severity,\n       fingerprint,\n       validity,\n       resolution,\n       assurance,\n       family,\n       ownership,\n       business_unit,\n       tree,\n       is_branch_audit\nFROM hardening_findings\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, subject_id, run_id, finding_id, title;"

type hardeningFindingsListParams struct {
	scopeIds string
}

func (q queries) hardeningFindingsList(ctx context.Context, conn *sql.Conn, p hardeningFindingsListParams) (*sql.Rows, error) {
	statement := hardeningFindingsListSQLite
	if q.dialect == dialectPostgres {
		statement = hardeningFindingsListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const impactAnalysisUpsertPostgres = "INSERT INTO traust_storage.impact_analysis (\n    binding_id,\n    artifact_digest,\n    metadata,\n    summary,\n    repos\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5\n)\nON CONFLICT (binding_id) DO NOTHING;"
const impactAnalysisUpsertSQLite = "INSERT INTO impact_analysis (\n    binding_id,\n    artifact_digest,\n    metadata,\n    summary,\n    repos\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type impactAnalysisUpsertParams struct {
	bindingId      string
	artifactDigest string
	metadata       string
	summary        string
	repos          string
}

func (q queries) impactAnalysisUpsert(ctx context.Context, conn *sql.Conn, p impactAnalysisUpsertParams) error {
	statement := impactAnalysisUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = impactAnalysisUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.metadata, p.summary, p.repos)
	return err
}

const isolationReviewUpsertPostgres = "INSERT INTO traust_storage.isolation_review (\n    binding_id,\n    artifact_digest,\n    title,\n    metadata,\n    interfaces,\n    gaps,\n    posture,\n    notes\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8\n)\nON CONFLICT (binding_id) DO NOTHING;"
const isolationReviewUpsertSQLite = "INSERT INTO isolation_review (\n    binding_id,\n    artifact_digest,\n    title,\n    metadata,\n    interfaces,\n    gaps,\n    posture,\n    notes\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type isolationReviewUpsertParams struct {
	bindingId      string
	artifactDigest string
	title          string
	metadata       string
	interfaces     string
	gaps           string
	posture        string
	notes          *string
}

func (q queries) isolationReviewUpsert(ctx context.Context, conn *sql.Conn, p isolationReviewUpsertParams) error {
	statement := isolationReviewUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = isolationReviewUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.title, p.metadata, p.interfaces, p.gaps, p.posture, p.notes)
	return err
}

const layerEventUpsertPostgres = "INSERT INTO traust_storage.layer_event (\n    binding_id,\n    artifact_digest,\n    event_id,\n    finding_ref,\n    fingerprint,\n    fingerprint_algo,\n    recorded_at,\n    occurred_at,\n    source_type,\n    source_ref,\n    actor_kind,\n    validity,\n    resolution,\n    evidence_grade,\n    auto_accept_tier,\n    rationale,\n    harness_version,\n    evidence_refs,\n    source_reported_by,\n    severity,\n    embargo,\n    risk_lambda,\n    risk_weights_version,\n    risk_tenancy_profile,\n    risk_profile_source,\n    alias,\n    finding,\n    restatement\n)\nVALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12,\n    $13,\n    $14,\n    $15,\n    $16,\n    $17,\n    $18,\n    $19,\n    $20,\n    $21,\n    $22,\n    $23,\n    $24,\n    $25,\n    $26,\n    $27,\n    $28\n)\nON CONFLICT (binding_id, event_id) DO NOTHING;"
const layerEventUpsertSQLite = "INSERT INTO layer_event (\n    binding_id,\n    artifact_digest,\n    event_id,\n    finding_ref,\n    fingerprint,\n    fingerprint_algo,\n    recorded_at,\n    occurred_at,\n    source_type,\n    source_ref,\n    actor_kind,\n    validity,\n    resolution,\n    evidence_grade,\n    auto_accept_tier,\n    rationale,\n    harness_version,\n    evidence_refs,\n    source_reported_by,\n    severity,\n    embargo,\n    risk_lambda,\n    risk_weights_version,\n    risk_tenancy_profile,\n    risk_profile_source,\n    alias,\n    finding,\n    restatement\n)\nVALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id, event_id) DO NOTHING;"

type layerEventUpsertParams struct {
	bindingId          string
	artifactDigest     string
	eventId            string
	findingRef         string
	fingerprint        *string
	fingerprintAlgo    *string
	recordedAt         string
	occurredAt         *string
	sourceType         *string
	sourceRef          *string
	actorKind          *string
	validity           *string
	resolution         *string
	evidenceGrade      *string
	autoAcceptTier     *int64
	rationale          *string
	harnessVersion     *string
	evidenceRefs       *string
	sourceReportedBy   *string
	severity           *string
	embargo            *string
	riskLambda         *float64
	riskWeightsVersion *string
	riskTenancyProfile *string
	riskProfileSource  *string
	alias              *string
	finding            *string
	restatement        *string
}

func (q queries) layerEventUpsert(ctx context.Context, conn *sql.Conn, p layerEventUpsertParams) error {
	statement := layerEventUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = layerEventUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.eventId, p.findingRef, p.fingerprint, p.fingerprintAlgo, p.recordedAt, p.occurredAt, p.sourceType, p.sourceRef, p.actorKind, p.validity, p.resolution, p.evidenceGrade, p.autoAcceptTier, p.rationale, p.harnessVersion, p.evidenceRefs, p.sourceReportedBy, p.severity, p.embargo, p.riskLambda, p.riskWeightsVersion, p.riskTenancyProfile, p.riskProfileSource, p.alias, p.finding, p.restatement)
	return err
}

const openFindingsListPostgres = "SELECT scope_id,\n       subject_id,\n       run_id,\n       finding_id,\n       title,\n       severity,\n       fingerprint,\n       validity,\n       resolution,\n       assurance,\n       family,\n       ownership,\n       business_unit,\n       tree,\n       is_branch_audit\nFROM traust_storage.open_findings\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, subject_id, run_id, finding_id, title;"
const openFindingsListSQLite = "SELECT scope_id,\n       subject_id,\n       run_id,\n       finding_id,\n       title,\n       severity,\n       fingerprint,\n       validity,\n       resolution,\n       assurance,\n       family,\n       ownership,\n       business_unit,\n       tree,\n       is_branch_audit\nFROM open_findings\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, subject_id, run_id, finding_id, title;"

type openFindingsListParams struct {
	scopeIds string
}

func (q queries) openFindingsList(ctx context.Context, conn *sql.Conn, p openFindingsListParams) (*sql.Rows, error) {
	statement := openFindingsListSQLite
	if q.dialect == dialectPostgres {
		statement = openFindingsListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const operatorPrivilegeListPostgres = "SELECT scope_id,\n       subject_id,\n       run_id,\n       repo,\n       tier,\n       workload_count,\n       privileged_or_host_workloads,\n       rbac_rule_count,\n       distinct_rule_triples,\n       distinct_cluster_triples,\n       cluster_scoped_rules,\n       wildcard_rules,\n       no_scc_request_recorded,\n       flag_secrets_access,\n       flag_nodes_access,\n       flag_wildcard_verbs,\n       flag_wildcard_resources,\n       flag_rbac_write,\n       flag_pods_exec,\n       flag_escalate_bind_impersonate,\n       ownership,\n       business_unit,\n       tree,\n       is_branch_audit\nFROM traust_storage.operator_privilege\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, subject_id, repo;"
const operatorPrivilegeListSQLite = "SELECT scope_id,\n       subject_id,\n       run_id,\n       repo,\n       tier,\n       workload_count,\n       privileged_or_host_workloads,\n       rbac_rule_count,\n       distinct_rule_triples,\n       distinct_cluster_triples,\n       cluster_scoped_rules,\n       wildcard_rules,\n       no_scc_request_recorded,\n       flag_secrets_access,\n       flag_nodes_access,\n       flag_wildcard_verbs,\n       flag_wildcard_resources,\n       flag_rbac_write,\n       flag_pods_exec,\n       flag_escalate_bind_impersonate,\n       ownership,\n       business_unit,\n       tree,\n       is_branch_audit\nFROM operator_privilege\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, subject_id, repo;"

type operatorPrivilegeListParams struct {
	scopeIds string
}

func (q queries) operatorPrivilegeList(ctx context.Context, conn *sql.Conn, p operatorPrivilegeListParams) (*sql.Rows, error) {
	statement := operatorPrivilegeListSQLite
	if q.dialect == dialectPostgres {
		statement = operatorPrivilegeListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const orgParametersUpsertPostgres = "INSERT INTO traust_storage.org_parameters (\n    binding_id,\n    artifact_digest,\n    version,\n    declared_by,\n    declared_on,\n    note,\n    parameters\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7\n)\nON CONFLICT (binding_id) DO NOTHING;"
const orgParametersUpsertSQLite = "INSERT INTO org_parameters (\n    binding_id,\n    artifact_digest,\n    version,\n    declared_by,\n    declared_on,\n    note,\n    parameters\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type orgParametersUpsertParams struct {
	bindingId      string
	artifactDigest string
	version        int64
	declaredBy     string
	declaredOn     *string
	note           *string
	parameters     string
}

func (q queries) orgParametersUpsert(ctx context.Context, conn *sql.Conn, p orgParametersUpsertParams) error {
	statement := orgParametersUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = orgParametersUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.version, p.declaredBy, p.declaredOn, p.note, p.parameters)
	return err
}

const patternExposureListPostgres = "SELECT scope_id,\n       tree,\n       ownership,\n       business_unit,\n       family,\n       cwe,\n       category,\n       severity,\n       effective_severity,\n       exposure_class,\n       occurrences,\n       distinct_fingerprints,\n       subjects\nFROM traust_storage.pattern_exposure\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, tree, family, cwe, severity;"
const patternExposureListSQLite = "SELECT scope_id,\n       tree,\n       ownership,\n       business_unit,\n       family,\n       cwe,\n       category,\n       severity,\n       effective_severity,\n       exposure_class,\n       occurrences,\n       distinct_fingerprints,\n       subjects\nFROM pattern_exposure\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, tree, family, cwe, severity;"

type patternExposureListParams struct {
	scopeIds string
}

func (q queries) patternExposureList(ctx context.Context, conn *sql.Conn, p patternExposureListParams) (*sql.Rows, error) {
	statement := patternExposureListSQLite
	if q.dialect == dialectPostgres {
		statement = patternExposureListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const pqcBlockersUpsertPostgres = "INSERT INTO traust_storage.pqc_blockers (\n    binding_id,\n    artifact_digest,\n    artifact,\n    title,\n    metadata,\n    executive_summary,\n    severity_criteria,\n    findings,\n    findings_summary,\n    remediation_roadmap\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10\n)\nON CONFLICT (binding_id) DO NOTHING;"
const pqcBlockersUpsertSQLite = "INSERT INTO pqc_blockers (\n    binding_id,\n    artifact_digest,\n    artifact,\n    title,\n    metadata,\n    executive_summary,\n    severity_criteria,\n    findings,\n    findings_summary,\n    remediation_roadmap\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type pqcBlockersUpsertParams struct {
	bindingId          string
	artifactDigest     string
	artifact           string
	title              string
	metadata           string
	executiveSummary   string
	severityCriteria   string
	findings           string
	findingsSummary    string
	remediationRoadmap string
}

func (q queries) pqcBlockersUpsert(ctx context.Context, conn *sql.Conn, p pqcBlockersUpsertParams) error {
	statement := pqcBlockersUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = pqcBlockersUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.artifact, p.title, p.metadata, p.executiveSummary, p.severityCriteria, p.findings, p.findingsSummary, p.remediationRoadmap)
	return err
}

const pqcDecisionTreeUpsertPostgres = "INSERT INTO traust_storage.pqc_decision_tree (\n    binding_id,\n    artifact_digest,\n    tree_version,\n    plan,\n    schema,\n    provenance_tree,\n    remediation_effort,\n    readiness_buckets,\n    tls_control_crosswalk,\n    fips_interaction,\n    pqc_classification_map,\n    server_side_caveat\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12\n)\nON CONFLICT (binding_id) DO NOTHING;"
const pqcDecisionTreeUpsertSQLite = "INSERT INTO pqc_decision_tree (\n    binding_id,\n    artifact_digest,\n    tree_version,\n    plan,\n    schema,\n    provenance_tree,\n    remediation_effort,\n    readiness_buckets,\n    tls_control_crosswalk,\n    fips_interaction,\n    pqc_classification_map,\n    server_side_caveat\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type pqcDecisionTreeUpsertParams struct {
	bindingId            string
	artifactDigest       string
	treeVersion          string
	plan                 *string
	schema               *string
	provenanceTree       string
	remediationEffort    string
	readinessBuckets     string
	tlsControlCrosswalk  string
	fipsInteraction      string
	pqcClassificationMap string
	serverSideCaveat     *string
}

func (q queries) pqcDecisionTreeUpsert(ctx context.Context, conn *sql.Conn, p pqcDecisionTreeUpsertParams) error {
	statement := pqcDecisionTreeUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = pqcDecisionTreeUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.treeVersion, p.plan, p.schema, p.provenanceTree, p.remediationEffort, p.readinessBuckets, p.tlsControlCrosswalk, p.fipsInteraction, p.pqcClassificationMap, p.serverSideCaveat)
	return err
}

const pqcFactsUpsertPostgres = "INSERT INTO traust_storage.pqc_facts (\n    binding_id,\n    artifact_digest,\n    artifact,\n    repository,\n    stamps,\n    coverage,\n    summary,\n    facts\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8\n)\nON CONFLICT (binding_id) DO NOTHING;"
const pqcFactsUpsertSQLite = "INSERT INTO pqc_facts (\n    binding_id,\n    artifact_digest,\n    artifact,\n    repository,\n    stamps,\n    coverage,\n    summary,\n    facts\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type pqcFactsUpsertParams struct {
	bindingId      string
	artifactDigest string
	artifact       string
	repository     string
	stamps         string
	coverage       string
	summary        string
	facts          string
}

func (q queries) pqcFactsUpsert(ctx context.Context, conn *sql.Conn, p pqcFactsUpsertParams) error {
	statement := pqcFactsUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = pqcFactsUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.artifact, p.repository, p.stamps, p.coverage, p.summary, p.facts)
	return err
}

const pqcPostureListPostgres = "SELECT scope_id,\n       subject_id,\n       readiness_bucket,\n       has_2030_clock,\n       hndl_priority,\n       runtime_verification_required,\n       dominant_provenance,\n       clock_items,\n       ownership,\n       business_unit,\n       tree,\n       is_branch_audit\nFROM traust_storage.pqc_posture\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, subject_id;"
const pqcPostureListSQLite = "SELECT scope_id,\n       subject_id,\n       readiness_bucket,\n       has_2030_clock,\n       hndl_priority,\n       runtime_verification_required,\n       dominant_provenance,\n       clock_items,\n       ownership,\n       business_unit,\n       tree,\n       is_branch_audit\nFROM pqc_posture\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, subject_id;"

type pqcPostureListParams struct {
	scopeIds string
}

func (q queries) pqcPostureList(ctx context.Context, conn *sql.Conn, p pqcPostureListParams) (*sql.Rows, error) {
	statement := pqcPostureListSQLite
	if q.dialect == dialectPostgres {
		statement = pqcPostureListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const pqcReadinessUpsertPostgres = "INSERT INTO traust_storage.pqc_readiness (\n    binding_id,\n    artifact_digest,\n    title,\n    metadata,\n    scores,\n    flags,\n    provenance_summary,\n    clock_items,\n    readiness_bucket,\n    fips_interaction,\n    runtime_evidence,\n    server_side_caveats,\n    notes,\n    remediations\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12,\n    $13,\n    $14\n)\nON CONFLICT (binding_id) DO NOTHING;"
const pqcReadinessUpsertSQLite = "INSERT INTO pqc_readiness (\n    binding_id,\n    artifact_digest,\n    title,\n    metadata,\n    scores,\n    flags,\n    provenance_summary,\n    clock_items,\n    readiness_bucket,\n    fips_interaction,\n    runtime_evidence,\n    server_side_caveats,\n    notes,\n    remediations\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type pqcReadinessUpsertParams struct {
	bindingId         string
	artifactDigest    string
	title             string
	metadata          string
	scores            string
	flags             string
	provenanceSummary string
	clockItems        *string
	readinessBucket   *string
	fipsInteraction   *string
	runtimeEvidence   *string
	serverSideCaveats *string
	notes             *string
	remediations      *string
}

func (q queries) pqcReadinessUpsert(ctx context.Context, conn *sql.Conn, p pqcReadinessUpsertParams) error {
	statement := pqcReadinessUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = pqcReadinessUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.title, p.metadata, p.scores, p.flags, p.provenanceSummary, p.clockItems, p.readinessBucket, p.fipsInteraction, p.runtimeEvidence, p.serverSideCaveats, p.notes, p.remediations)
	return err
}

const pqcReadinessRollupListPostgres = "SELECT scope_id,\n       tree,\n       ownership,\n       business_unit,\n       readiness_bucket,\n       subjects,\n       with_2030_clock,\n       hndl_priority,\n       clock_items\nFROM traust_storage.pqc_readiness_rollup\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, tree, readiness_bucket;"
const pqcReadinessRollupListSQLite = "SELECT scope_id,\n       tree,\n       ownership,\n       business_unit,\n       readiness_bucket,\n       subjects,\n       with_2030_clock,\n       hndl_priority,\n       clock_items\nFROM pqc_readiness_rollup\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, tree, readiness_bucket;"

type pqcReadinessRollupListParams struct {
	scopeIds string
}

func (q queries) pqcReadinessRollupList(ctx context.Context, conn *sql.Conn, p pqcReadinessRollupListParams) (*sql.Rows, error) {
	statement := pqcReadinessRollupListSQLite
	if q.dialect == dialectPostgres {
		statement = pqcReadinessRollupListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const privProfileUpsertPostgres = "INSERT INTO traust_storage.priv_profile (\n    binding_id,\n    artifact_digest,\n    repo,\n    tier,\n    workloads,\n    rbac_rules,\n    rbac_flags,\n    scc_requests,\n    sccs_shipped,\n    namespaces,\n    install_modes,\n    operatorgroups,\n    tier2_required_vs_granted,\n    example_or_test_manifests_excluded,\n    summary\n)\nVALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12,\n    $13,\n    $14,\n    $15\n)\nON CONFLICT (binding_id) DO NOTHING;"
const privProfileUpsertSQLite = "INSERT INTO priv_profile (\n    binding_id,\n    artifact_digest,\n    repo,\n    tier,\n    workloads,\n    rbac_rules,\n    rbac_flags,\n    scc_requests,\n    sccs_shipped,\n    namespaces,\n    install_modes,\n    operatorgroups,\n    tier2_required_vs_granted,\n    example_or_test_manifests_excluded,\n    summary\n)\nVALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type privProfileUpsertParams struct {
	bindingId                      string
	artifactDigest                 string
	repo                           string
	tier                           *string
	workloads                      *string
	rbacRules                      *string
	rbacFlags                      *string
	sccRequests                    *string
	sccsShipped                    *string
	namespaces                     *string
	installModes                   *string
	operatorgroups                 *string
	tier2RequiredVsGranted         *string
	exampleOrTestManifestsExcluded *string
	summary                        *string
}

func (q queries) privProfileUpsert(ctx context.Context, conn *sql.Conn, p privProfileUpsertParams) error {
	statement := privProfileUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = privProfileUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.repo, p.tier, p.workloads, p.rbacRules, p.rbacFlags, p.sccRequests, p.sccsShipped, p.namespaces, p.installModes, p.operatorgroups, p.tier2RequiredVsGranted, p.exampleOrTestManifestsExcluded, p.summary)
	return err
}

const refutedRegisterUpsertPostgres = "INSERT INTO traust_storage.refuted_register (\n    binding_id, artifact_digest, source, sources, generated_at, entries\n) VALUES (\n    $1, $2, $3, $4, $5, $6\n)\nON CONFLICT (binding_id) DO NOTHING;"
const refutedRegisterUpsertSQLite = "INSERT INTO refuted_register (\n    binding_id, artifact_digest, source, sources, generated_at, entries\n) VALUES (\n    ?, ?, ?, ?, ?, ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type refutedRegisterUpsertParams struct {
	bindingId      string
	artifactDigest string
	source         string
	sources        *string
	generatedAt    string
	entries        string
}

func (q queries) refutedRegisterUpsert(ctx context.Context, conn *sql.Conn, p refutedRegisterUpsertParams) error {
	statement := refutedRegisterUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = refutedRegisterUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.source, p.sources, p.generatedAt, p.entries)
	return err
}

const remediationUpsertPostgres = "INSERT INTO traust_storage.remediation (\n    binding_id,\n    artifact_digest,\n    title,\n    metadata,\n    source_findings,\n    fork,\n    patch,\n    checks,\n    evidence,\n    revalidation,\n    pull_request,\n    summary,\n    notes,\n    footer\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12,\n    $13,\n    $14\n)\nON CONFLICT (binding_id) DO NOTHING;"
const remediationUpsertSQLite = "INSERT INTO remediation (\n    binding_id,\n    artifact_digest,\n    title,\n    metadata,\n    source_findings,\n    fork,\n    patch,\n    checks,\n    evidence,\n    revalidation,\n    pull_request,\n    summary,\n    notes,\n    footer\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type remediationUpsertParams struct {
	bindingId      string
	artifactDigest string
	title          string
	metadata       string
	sourceFindings string
	fork           string
	patch          string
	checks         string
	evidence       *string
	revalidation   *string
	pullRequest    *string
	summary        string
	notes          *string
	footer         *string
}

func (q queries) remediationUpsert(ctx context.Context, conn *sql.Conn, p remediationUpsertParams) error {
	statement := remediationUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = remediationUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.title, p.metadata, p.sourceFindings, p.fork, p.patch, p.checks, p.evidence, p.revalidation, p.pullRequest, p.summary, p.notes, p.footer)
	return err
}

const remediationCurrentListPostgres = "SELECT scope_id,\n       subject_id,\n       run_id,\n       finding_ref,\n       title,\n       severity,\n       cwes,\n       locations,\n       triage_confidence,\n       validation_verdict,\n       audit_report_path,\n       triage_report_path,\n       validation_report_path,\n       ownership,\n       business_unit,\n       tree,\n       product,\n       is_branch_audit\nFROM traust_storage.remediation_current\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, subject_id, finding_ref;"
const remediationCurrentListSQLite = "SELECT scope_id,\n       subject_id,\n       run_id,\n       finding_ref,\n       title,\n       severity,\n       cwes,\n       locations,\n       triage_confidence,\n       validation_verdict,\n       audit_report_path,\n       triage_report_path,\n       validation_report_path,\n       ownership,\n       business_unit,\n       tree,\n       product,\n       is_branch_audit\nFROM remediation_current\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, subject_id, finding_ref;"

type remediationCurrentListParams struct {
	scopeIds string
}

func (q queries) remediationCurrentList(ctx context.Context, conn *sql.Conn, p remediationCurrentListParams) (*sql.Rows, error) {
	statement := remediationCurrentListSQLite
	if q.dialect == dialectPostgres {
		statement = remediationCurrentListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const remediationSourceUpsertPostgres = "INSERT INTO traust_storage.remediation_source (\n    binding_id,\n    artifact_digest,\n    finding_ref,\n    title,\n    severity,\n    cwes,\n    locations,\n    triage_confidence,\n    validation_verdict,\n    audit_report_path,\n    triage_report_path,\n    validation_report_path\n)\nVALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12\n)\nON CONFLICT (binding_id, finding_ref) DO NOTHING;"
const remediationSourceUpsertSQLite = "INSERT INTO remediation_source (\n    binding_id,\n    artifact_digest,\n    finding_ref,\n    title,\n    severity,\n    cwes,\n    locations,\n    triage_confidence,\n    validation_verdict,\n    audit_report_path,\n    triage_report_path,\n    validation_report_path\n)\nVALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id, finding_ref) DO NOTHING;"

type remediationSourceUpsertParams struct {
	bindingId            string
	artifactDigest       string
	findingRef           string
	title                *string
	severity             *string
	cwes                 *string
	locations            *string
	triageConfidence     *float64
	validationVerdict    *string
	auditReportPath      *string
	triageReportPath     *string
	validationReportPath *string
}

func (q queries) remediationSourceUpsert(ctx context.Context, conn *sql.Conn, p remediationSourceUpsertParams) error {
	statement := remediationSourceUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = remediationSourceUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.findingRef, p.title, p.severity, p.cwes, p.locations, p.triageConfidence, p.validationVerdict, p.auditReportPath, p.triageReportPath, p.validationReportPath)
	return err
}

const reportUpsertPostgres = "INSERT INTO traust_storage.report (\n    binding_id,\n    artifact_digest,\n    title,\n    metadata,\n    executive_summary,\n    severity_criteria,\n    findings,\n    findings_summary,\n    remediation_roadmap,\n    dependency_audit,\n    negative_results,\n    asvs_coverage,\n    scanner_correlation,\n    peach_isolation_review,\n    disposition_summary,\n    footer\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12,\n    $13,\n    $14,\n    $15,\n    $16\n)\nON CONFLICT (binding_id) DO NOTHING;"
const reportUpsertSQLite = "INSERT INTO report (\n    binding_id,\n    artifact_digest,\n    title,\n    metadata,\n    executive_summary,\n    severity_criteria,\n    findings,\n    findings_summary,\n    remediation_roadmap,\n    dependency_audit,\n    negative_results,\n    asvs_coverage,\n    scanner_correlation,\n    peach_isolation_review,\n    disposition_summary,\n    footer\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type reportUpsertParams struct {
	bindingId            string
	artifactDigest       string
	title                string
	metadata             string
	executiveSummary     string
	severityCriteria     string
	findings             string
	findingsSummary      string
	remediationRoadmap   string
	dependencyAudit      *string
	negativeResults      *string
	asvsCoverage         *string
	scannerCorrelation   *string
	peachIsolationReview *string
	dispositionSummary   *string
	footer               *string
}

func (q queries) reportUpsert(ctx context.Context, conn *sql.Conn, p reportUpsertParams) error {
	statement := reportUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = reportUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.title, p.metadata, p.executiveSummary, p.severityCriteria, p.findings, p.findingsSummary, p.remediationRoadmap, p.dependencyAudit, p.negativeResults, p.asvsCoverage, p.scannerCorrelation, p.peachIsolationReview, p.dispositionSummary, p.footer)
	return err
}

const reportFindingUpsertPostgres = "INSERT INTO traust_storage.report_finding (\n    binding_id,\n    artifact_digest,\n    finding_id,\n    title,\n    severity,\n    fingerprint,\n    validation_status,\n    validity,\n    resolution,\n    assurance,\n    last_updated,\n    conflict,\n    fp_overridden,\n    fp_reassertion_blocked,\n    refuted_awaiting_signoff,\n    severity_override,\n    description,\n    remediation,\n    category,\n    cwes,\n    locations,\n    asvs_references,\n    peach_references,\n    capec,\n    attack_pattern,\n    cvss,\n    evidence,\n    effective_severity,\n    origin,\n    source_findings,\n    passes,\n    remediation_effort,\n    pqc_classification,\n    fingerprint_algo,\n    isolation_boundary,\n    isolation_dimensions,\n    dependency\n)\nVALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12,\n    $13,\n    $14,\n    $15,\n    $16,\n    $17,\n    $18,\n    $19,\n    $20,\n    $21,\n    $22,\n    $23,\n    $24,\n    $25,\n    $26,\n    $27,\n    $28,\n    $29,\n    $30,\n    $31,\n    $32,\n    $33,\n    $34,\n    $35,\n    $36,\n    $37\n)\nON CONFLICT (binding_id, finding_id) DO NOTHING;"
const reportFindingUpsertSQLite = "INSERT INTO report_finding (\n    binding_id,\n    artifact_digest,\n    finding_id,\n    title,\n    severity,\n    fingerprint,\n    validation_status,\n    validity,\n    resolution,\n    assurance,\n    last_updated,\n    conflict,\n    fp_overridden,\n    fp_reassertion_blocked,\n    refuted_awaiting_signoff,\n    severity_override,\n    description,\n    remediation,\n    category,\n    cwes,\n    locations,\n    asvs_references,\n    peach_references,\n    capec,\n    attack_pattern,\n    cvss,\n    evidence,\n    effective_severity,\n    origin,\n    source_findings,\n    passes,\n    remediation_effort,\n    pqc_classification,\n    fingerprint_algo,\n    isolation_boundary,\n    isolation_dimensions,\n    dependency\n)\nVALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id, finding_id) DO NOTHING;"

type reportFindingUpsertParams struct {
	bindingId              string
	artifactDigest         string
	findingId              string
	title                  *string
	severity               *string
	fingerprint            *string
	validationStatus       *string
	validity               *string
	resolution             *string
	assurance              *string
	lastUpdated            *string
	conflict               *int64
	fpOverridden           *int64
	fpReassertionBlocked   *int64
	refutedAwaitingSignoff *int64
	severityOverride       *string
	description            *string
	remediation            *string
	category               *string
	cwes                   *string
	locations              *string
	asvsReferences         *string
	peachReferences        *string
	capec                  *string
	attackPattern          *string
	cvss                   *string
	evidence               *string
	effectiveSeverity      *string
	origin                 *string
	sourceFindings         *string
	passes                 *string
	remediationEffort      *string
	pqcClassification      *string
	fingerprintAlgo        *string
	isolationBoundary      *string
	isolationDimensions    *string
	dependency             *string
}

func (q queries) reportFindingUpsert(ctx context.Context, conn *sql.Conn, p reportFindingUpsertParams) error {
	statement := reportFindingUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = reportFindingUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.findingId, p.title, p.severity, p.fingerprint, p.validationStatus, p.validity, p.resolution, p.assurance, p.lastUpdated, p.conflict, p.fpOverridden, p.fpReassertionBlocked, p.refutedAwaitingSignoff, p.severityOverride, p.description, p.remediation, p.category, p.cwes, p.locations, p.asvsReferences, p.peachReferences, p.capec, p.attackPattern, p.cvss, p.evidence, p.effectiveSeverity, p.origin, p.sourceFindings, p.passes, p.remediationEffort, p.pqcClassification, p.fingerprintAlgo, p.isolationBoundary, p.isolationDimensions, p.dependency)
	return err
}

const riskRatingMethodologyUpsertPostgres = "INSERT INTO traust_storage.risk_rating_methodology (\n    binding_id,\n    artifact_digest,\n    methodology,\n    methodology_version,\n    source,\n    documentation,\n    schema,\n    bands,\n    bucket_thresholds,\n    likelihood_factors,\n    impact_factors,\n    matrix,\n    fallback,\n    threat_intel_factor\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12,\n    $13,\n    $14\n)\nON CONFLICT (binding_id) DO NOTHING;"
const riskRatingMethodologyUpsertSQLite = "INSERT INTO risk_rating_methodology (\n    binding_id,\n    artifact_digest,\n    methodology,\n    methodology_version,\n    source,\n    documentation,\n    schema,\n    bands,\n    bucket_thresholds,\n    likelihood_factors,\n    impact_factors,\n    matrix,\n    fallback,\n    threat_intel_factor\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type riskRatingMethodologyUpsertParams struct {
	bindingId          string
	artifactDigest     string
	methodology        string
	methodologyVersion string
	source             string
	documentation      *string
	schema             *string
	bands              string
	bucketThresholds   string
	likelihoodFactors  string
	impactFactors      string
	matrix             string
	fallback           string
	threatIntelFactor  *string
}

func (q queries) riskRatingMethodologyUpsert(ctx context.Context, conn *sql.Conn, p riskRatingMethodologyUpsertParams) error {
	statement := riskRatingMethodologyUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = riskRatingMethodologyUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.methodology, p.methodologyVersion, p.source, p.documentation, p.schema, p.bands, p.bucketThresholds, p.likelihoodFactors, p.impactFactors, p.matrix, p.fallback, p.threatIntelFactor)
	return err
}

const scopeSetPostgres = "SELECT set_config('traust.scope_ids', $1, true);"
const scopeSetSQLite = "SELECT ?;"

type scopeSetParams struct {
	scopeIds string
}

func (q queries) scopeSet(ctx context.Context, conn *sql.Conn, p scopeSetParams) error {
	statement := scopeSetSQLite
	if q.dialect == dialectPostgres {
		statement = scopeSetPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.scopeIds)
	return err
}

const slaPolicyUpsertPostgres = "INSERT INTO traust_storage.sla_policy (\n    binding_id,\n    artifact_digest,\n    policy_name,\n    source,\n    severity_mapping,\n    clock_start,\n    profiles\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7\n)\nON CONFLICT (binding_id) DO NOTHING;"
const slaPolicyUpsertSQLite = "INSERT INTO sla_policy (\n    binding_id,\n    artifact_digest,\n    policy_name,\n    source,\n    severity_mapping,\n    clock_start,\n    profiles\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type slaPolicyUpsertParams struct {
	bindingId       string
	artifactDigest  string
	policyName      string
	source          string
	severityMapping string
	clockStart      *string
	profiles        string
}

func (q queries) slaPolicyUpsert(ctx context.Context, conn *sql.Conn, p slaPolicyUpsertParams) error {
	statement := slaPolicyUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = slaPolicyUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.policyName, p.source, p.severityMapping, p.clockStart, p.profiles)
	return err
}

const slaThresholdListPostgres = "SELECT scope_id,\n       policy_name,\n       profile_name,\n       clock_start,\n       severity,\n       resolve_days,\n       acknowledge_days\nFROM traust_storage.sla_threshold\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, severity;"
const slaThresholdListSQLite = "SELECT scope_id,\n       policy_name,\n       profile_name,\n       clock_start,\n       severity,\n       resolve_days,\n       acknowledge_days\nFROM sla_threshold\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, severity;"

type slaThresholdListParams struct {
	scopeIds string
}

func (q queries) slaThresholdList(ctx context.Context, conn *sql.Conn, p slaThresholdListParams) (*sql.Rows, error) {
	statement := slaThresholdListSQLite
	if q.dialect == dialectPostgres {
		statement = slaThresholdListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const subjectOwnershipUpsertPostgres = "INSERT INTO traust_storage.subject_ownership (\n    binding_id,\n    artifact_digest,\n    subject_id,\n    tree,\n    ownership,\n    business_unit,\n    label,\n    product,\n    repo_url,\n    ref,\n    ref_kind,\n    is_branch_audit\n)\nVALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12\n)\nON CONFLICT (binding_id, subject_id) DO NOTHING;"
const subjectOwnershipUpsertSQLite = "INSERT INTO subject_ownership (\n    binding_id,\n    artifact_digest,\n    subject_id,\n    tree,\n    ownership,\n    business_unit,\n    label,\n    product,\n    repo_url,\n    ref,\n    ref_kind,\n    is_branch_audit\n)\nVALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id, subject_id) DO NOTHING;"

type subjectOwnershipUpsertParams struct {
	bindingId      string
	artifactDigest string
	subjectId      string
	tree           string
	ownership      string
	businessUnit   string
	label          *string
	product        *string
	repoUrl        *string
	ref            *string
	refKind        *string
	isBranchAudit  *int64
}

func (q queries) subjectOwnershipUpsert(ctx context.Context, conn *sql.Conn, p subjectOwnershipUpsertParams) error {
	statement := subjectOwnershipUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = subjectOwnershipUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.subjectId, p.tree, p.ownership, p.businessUnit, p.label, p.product, p.repoUrl, p.ref, p.refKind, p.isBranchAudit)
	return err
}

const threatUpsertPostgres = "INSERT INTO traust_storage.threat (\n    binding_id,\n    artifact_digest,\n    threat_key,\n    threat_id,\n    model,\n    subject_id,\n    product,\n    statement,\n    surface,\n    asset,\n    impact,\n    likelihood,\n    status,\n    controls,\n    actors,\n    evidence,\n    linddun,\n    score,\n    attack_refs,\n    isolation_dimensions,\n    isolation_boundaries\n)\nVALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12,\n    $13,\n    $14,\n    $15,\n    $16,\n    $17,\n    $18,\n    $19,\n    $20,\n    $21\n)\nON CONFLICT (binding_id, threat_key) DO NOTHING;"
const threatUpsertSQLite = "INSERT INTO threat (\n    binding_id,\n    artifact_digest,\n    threat_key,\n    threat_id,\n    model,\n    subject_id,\n    product,\n    statement,\n    surface,\n    asset,\n    impact,\n    likelihood,\n    status,\n    controls,\n    actors,\n    evidence,\n    linddun,\n    score,\n    attack_refs,\n    isolation_dimensions,\n    isolation_boundaries\n)\nVALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id, threat_key) DO NOTHING;"

type threatUpsertParams struct {
	bindingId           string
	artifactDigest      string
	threatKey           string
	threatId            string
	model               string
	subjectId           *string
	product             *string
	statement           *string
	surface             *string
	asset               *string
	impact              *string
	likelihood          *string
	status              *string
	controls            *string
	actors              *string
	evidence            *string
	linddun             *int64
	score               *int64
	attackRefs          *string
	isolationDimensions *string
	isolationBoundaries *string
}

func (q queries) threatUpsert(ctx context.Context, conn *sql.Conn, p threatUpsertParams) error {
	statement := threatUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = threatUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.threatKey, p.threatId, p.model, p.subjectId, p.product, p.statement, p.surface, p.asset, p.impact, p.likelihood, p.status, p.controls, p.actors, p.evidence, p.linddun, p.score, p.attackRefs, p.isolationDimensions, p.isolationBoundaries)
	return err
}

const threatCurrentListPostgres = "SELECT scope_id,\n       threat_key,\n       threat_id,\n       model,\n       subject_id,\n       product,\n       statement,\n       surface,\n       asset,\n       impact,\n       likelihood,\n       status,\n       controls,\n       evidence,\n       attack_refs,\n       linddun,\n       score,\n       isolation_dimensions,\n       isolation_boundaries,\n       ownership,\n       business_unit,\n       tree,\n       is_branch_audit\nFROM traust_storage.threat_current\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, threat_key;"
const threatCurrentListSQLite = "SELECT scope_id,\n       threat_key,\n       threat_id,\n       model,\n       subject_id,\n       product,\n       statement,\n       surface,\n       asset,\n       impact,\n       likelihood,\n       status,\n       controls,\n       evidence,\n       attack_refs,\n       linddun,\n       score,\n       isolation_dimensions,\n       isolation_boundaries,\n       ownership,\n       business_unit,\n       tree,\n       is_branch_audit\nFROM threat_current\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, threat_key;"

type threatCurrentListParams struct {
	scopeIds string
}

func (q queries) threatCurrentList(ctx context.Context, conn *sql.Conn, p threatCurrentListParams) (*sql.Rows, error) {
	statement := threatCurrentListSQLite
	if q.dialect == dialectPostgres {
		statement = threatCurrentListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const threatExposureListPostgres = "SELECT scope_id,\n       tree,\n       ownership,\n       business_unit,\n       product,\n       impact,\n       likelihood,\n       status,\n       evidenced,\n       linddun,\n       threats,\n       subjects,\n       top_score\nFROM traust_storage.threat_exposure\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, tree, product, impact, likelihood, status;"
const threatExposureListSQLite = "SELECT scope_id,\n       tree,\n       ownership,\n       business_unit,\n       product,\n       impact,\n       likelihood,\n       status,\n       evidenced,\n       linddun,\n       threats,\n       subjects,\n       top_score\nFROM threat_exposure\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, tree, product, impact, likelihood, status;"

type threatExposureListParams struct {
	scopeIds string
}

func (q queries) threatExposureList(ctx context.Context, conn *sql.Conn, p threatExposureListParams) (*sql.Rows, error) {
	statement := threatExposureListSQLite
	if q.dialect == dialectPostgres {
		statement = threatExposureListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const traustStorageMetaExistsPostgres = "SELECT to_regclass('traust_storage.traust_storage_meta');"
const traustStorageMetaExistsSQLite = "SELECT name\nFROM sqlite_master\nWHERE type = 'table' AND name = 'traust_storage_meta';"

type traustStorageMetaExistsParams struct {
}

func (q queries) traustStorageMetaExists(ctx context.Context, conn *sql.Conn, p traustStorageMetaExistsParams) *sql.Row {
	statement := traustStorageMetaExistsSQLite
	if q.dialect == dialectPostgres {
		statement = traustStorageMetaExistsPostgres
	}
	return conn.QueryRowContext(ctx, statement)
}

const traustStorageMetaGetPostgres = "SELECT contract_version, revision\nFROM traust_storage.traust_storage_meta\nWHERE id = 1;"
const traustStorageMetaGetSQLite = "SELECT contract_version, revision\nFROM traust_storage_meta\nWHERE id = 1;"

type traustStorageMetaGetParams struct {
}

func (q queries) traustStorageMetaGet(ctx context.Context, conn *sql.Conn, p traustStorageMetaGetParams) *sql.Row {
	statement := traustStorageMetaGetSQLite
	if q.dialect == dialectPostgres {
		statement = traustStorageMetaGetPostgres
	}
	return conn.QueryRowContext(ctx, statement)
}

const traustStorageMetaLockPostgres = "-- Reserved bootstrap lock shared by storage hosts; the stable key is arbitrary, not a hash.\nSELECT pg_advisory_xact_lock(741829301);"
const traustStorageMetaLockSQLite = ""

type traustStorageMetaLockParams struct {
}

func (q queries) traustStorageMetaLock(ctx context.Context, conn *sql.Conn, p traustStorageMetaLockParams) error {
	statement := traustStorageMetaLockSQLite
	if q.dialect == dialectPostgres {
		statement = traustStorageMetaLockPostgres
	}
	_, err := conn.ExecContext(ctx, statement)
	return err
}

const traustStorageMetaUpsertPostgres = "INSERT INTO traust_storage.traust_storage_meta (\n    id,\n    contract_version,\n    revision,\n    applied_at\n)\nVALUES (\n    1,\n    $1,\n    $2,\n    $3\n)\nON CONFLICT (id) DO UPDATE SET\n    contract_version = EXCLUDED.contract_version,\n    revision = EXCLUDED.revision,\n    applied_at = EXCLUDED.applied_at;"
const traustStorageMetaUpsertSQLite = "INSERT INTO traust_storage_meta (\n    id,\n    contract_version,\n    revision,\n    applied_at\n)\nVALUES (\n    1,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (id) DO UPDATE SET\n    contract_version = EXCLUDED.contract_version,\n    revision = EXCLUDED.revision,\n    applied_at = EXCLUDED.applied_at;"

type traustStorageMetaUpsertParams struct {
	contractVersion string
	revision        int64
	appliedAt       string
}

func (q queries) traustStorageMetaUpsert(ctx context.Context, conn *sql.Conn, p traustStorageMetaUpsertParams) error {
	statement := traustStorageMetaUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = traustStorageMetaUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.contractVersion, p.revision, p.appliedAt)
	return err
}

const triageVerdictUpsertPostgres = "INSERT INTO traust_storage.triage_verdict (\n    binding_id,\n    artifact_digest,\n    finding_id,\n    source_finding_id,\n    triage_completed,\n    verdict,\n    severity,\n    vote_breakdown,\n    rationale\n)\nVALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9\n)\nON CONFLICT (binding_id, finding_id) DO NOTHING;"
const triageVerdictUpsertSQLite = "INSERT INTO triage_verdict (\n    binding_id,\n    artifact_digest,\n    finding_id,\n    source_finding_id,\n    triage_completed,\n    verdict,\n    severity,\n    vote_breakdown,\n    rationale\n)\nVALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id, finding_id) DO NOTHING;"

type triageVerdictUpsertParams struct {
	bindingId       string
	artifactDigest  string
	findingId       string
	sourceFindingId *string
	triageCompleted string
	verdict         string
	severity        *string
	voteBreakdown   *string
	rationale       *string
}

func (q queries) triageVerdictUpsert(ctx context.Context, conn *sql.Conn, p triageVerdictUpsertParams) error {
	statement := triageVerdictUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = triageVerdictUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.findingId, p.sourceFindingId, p.triageCompleted, p.verdict, p.severity, p.voteBreakdown, p.rationale)
	return err
}

const validationUpsertPostgres = "INSERT INTO traust_storage.validation (\n    binding_id,\n    artifact_digest,\n    title,\n    metadata,\n    source_reports,\n    summary,\n    validated_findings,\n    attack_chains,\n    novel_findings,\n    negative_results,\n    execution_log_ref,\n    execution_log_sha256,\n    footer\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12,\n    $13\n)\nON CONFLICT (binding_id) DO NOTHING;"
const validationUpsertSQLite = "INSERT INTO validation (\n    binding_id,\n    artifact_digest,\n    title,\n    metadata,\n    source_reports,\n    summary,\n    validated_findings,\n    attack_chains,\n    novel_findings,\n    negative_results,\n    execution_log_ref,\n    execution_log_sha256,\n    footer\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type validationUpsertParams struct {
	bindingId          string
	artifactDigest     string
	title              string
	metadata           string
	sourceReports      string
	summary            string
	validatedFindings  string
	attackChains       string
	novelFindings      string
	negativeResults    *string
	executionLogRef    string
	executionLogSha256 *string
	footer             *string
}

func (q queries) validationUpsert(ctx context.Context, conn *sql.Conn, p validationUpsertParams) error {
	statement := validationUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = validationUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.title, p.metadata, p.sourceReports, p.summary, p.validatedFindings, p.attackChains, p.novelFindings, p.negativeResults, p.executionLogRef, p.executionLogSha256, p.footer)
	return err
}

const validationCurrentListPostgres = "SELECT scope_id,\n       subject_id,\n       run_id,\n       target_environment,\n       source_id,\n       source_finding_id,\n       title,\n       claimed_severity,\n       surface,\n       verdict,\n       skip_reason,\n       technique,\n       observed_impact,\n       evidence_grade,\n       grade_rationale,\n       soundness_flag,\n       severity_validation,\n       deviation_from_claim,\n       rollback_performed,\n       chain_context,\n       not_attempted_reason,\n       ownership,\n       business_unit,\n       tree,\n       product,\n       is_branch_audit\nFROM traust_storage.validation_current\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, subject_id, target_environment, source_id;"
const validationCurrentListSQLite = "SELECT scope_id,\n       subject_id,\n       run_id,\n       target_environment,\n       source_id,\n       source_finding_id,\n       title,\n       claimed_severity,\n       surface,\n       verdict,\n       skip_reason,\n       technique,\n       observed_impact,\n       evidence_grade,\n       grade_rationale,\n       soundness_flag,\n       severity_validation,\n       deviation_from_claim,\n       rollback_performed,\n       chain_context,\n       not_attempted_reason,\n       ownership,\n       business_unit,\n       tree,\n       product,\n       is_branch_audit\nFROM validation_current\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, subject_id, target_environment, source_id;"

type validationCurrentListParams struct {
	scopeIds string
}

func (q queries) validationCurrentList(ctx context.Context, conn *sql.Conn, p validationCurrentListParams) (*sql.Rows, error) {
	statement := validationCurrentListSQLite
	if q.dialect == dialectPostgres {
		statement = validationCurrentListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const validationExposureListPostgres = "SELECT scope_id,\n       target_environment,\n       tree,\n       ownership,\n       business_unit,\n       product,\n       claimed_severity,\n       verdict,\n       attempted,\n       skip_reason,\n       findings,\n       subjects,\n       distinct_claims\nFROM traust_storage.validation_exposure\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, target_environment, tree, product, claimed_severity, verdict;"
const validationExposureListSQLite = "SELECT scope_id,\n       target_environment,\n       tree,\n       ownership,\n       business_unit,\n       product,\n       claimed_severity,\n       verdict,\n       attempted,\n       skip_reason,\n       findings,\n       subjects,\n       distinct_claims\nFROM validation_exposure\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, target_environment, tree, product, claimed_severity, verdict;"

type validationExposureListParams struct {
	scopeIds string
}

func (q queries) validationExposureList(ctx context.Context, conn *sql.Conn, p validationExposureListParams) (*sql.Rows, error) {
	statement := validationExposureListSQLite
	if q.dialect == dialectPostgres {
		statement = validationExposureListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const validationFindingUpsertPostgres = "INSERT INTO traust_storage.validation_finding (\n    binding_id,\n    artifact_digest,\n    source_id,\n    source_finding_id,\n    title,\n    claimed_severity,\n    surface,\n    verdict,\n    skip_reason,\n    technique,\n    observed_impact,\n    evidence_grade,\n    grade_rationale,\n    soundness_flag,\n    severity_validation,\n    deviation_from_claim,\n    rollback_performed,\n    chain_context,\n    not_attempted_reason\n)\nVALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12,\n    $13,\n    $14,\n    $15,\n    $16,\n    $17,\n    $18,\n    $19\n)\nON CONFLICT (binding_id, source_id) DO NOTHING;"
const validationFindingUpsertSQLite = "INSERT INTO validation_finding (\n    binding_id,\n    artifact_digest,\n    source_id,\n    source_finding_id,\n    title,\n    claimed_severity,\n    surface,\n    verdict,\n    skip_reason,\n    technique,\n    observed_impact,\n    evidence_grade,\n    grade_rationale,\n    soundness_flag,\n    severity_validation,\n    deviation_from_claim,\n    rollback_performed,\n    chain_context,\n    not_attempted_reason\n)\nVALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id, source_id) DO NOTHING;"

type validationFindingUpsertParams struct {
	bindingId          string
	artifactDigest     string
	sourceId           string
	sourceFindingId    *string
	title              *string
	claimedSeverity    *string
	surface            *string
	verdict            *string
	skipReason         *string
	technique          *string
	observedImpact     *string
	evidenceGrade      *string
	gradeRationale     *string
	soundnessFlag      *string
	severityValidation *string
	deviationFromClaim *string
	rollbackPerformed  *int64
	chainContext       *string
	notAttemptedReason *string
}

func (q queries) validationFindingUpsert(ctx context.Context, conn *sql.Conn, p validationFindingUpsertParams) error {
	statement := validationFindingUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = validationFindingUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.sourceId, p.sourceFindingId, p.title, p.claimedSeverity, p.surface, p.verdict, p.skipReason, p.technique, p.observedImpact, p.evidenceGrade, p.gradeRationale, p.soundnessFlag, p.severityValidation, p.deviationFromClaim, p.rollbackPerformed, p.chainContext, p.notAttemptedReason)
	return err
}

const verificationUpsertPostgres = "INSERT INTO traust_storage.verification (\n    binding_id,\n    artifact_digest,\n    title,\n    metadata,\n    summary,\n    verified_findings,\n    regressions,\n    commit_timeline,\n    evidence,\n    recommendations,\n    notes,\n    footer\n) VALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12\n)\nON CONFLICT (binding_id) DO NOTHING;"
const verificationUpsertSQLite = "INSERT INTO verification (\n    binding_id,\n    artifact_digest,\n    title,\n    metadata,\n    summary,\n    verified_findings,\n    regressions,\n    commit_timeline,\n    evidence,\n    recommendations,\n    notes,\n    footer\n) VALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id) DO NOTHING;"

type verificationUpsertParams struct {
	bindingId        string
	artifactDigest   string
	title            string
	metadata         string
	summary          string
	verifiedFindings string
	regressions      string
	commitTimeline   string
	evidence         *string
	recommendations  *string
	notes            *string
	footer           *string
}

func (q queries) verificationUpsert(ctx context.Context, conn *sql.Conn, p verificationUpsertParams) error {
	statement := verificationUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = verificationUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.title, p.metadata, p.summary, p.verifiedFindings, p.regressions, p.commitTimeline, p.evidence, p.recommendations, p.notes, p.footer)
	return err
}

const verificationCurrentListPostgres = "SELECT scope_id,\n       subject_id,\n       run_id,\n       original_id,\n       original_title,\n       original_severity,\n       verdict,\n       held,\n       unattributed,\n       remediation_commits,\nevidence_explanation,\n       evidence_framework_reference,\n       evidence_original_code,\n       evidence_patched_code,\n       disposition_rationale,\n       residual_risk,\n       residual_severity,\n       cross_repo,\n       ownership,\n       business_unit,\n       tree,\n       product,\n       is_branch_audit\nFROM traust_storage.verification_current\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, subject_id, original_id;"
const verificationCurrentListSQLite = "SELECT scope_id,\n       subject_id,\n       run_id,\n       original_id,\n       original_title,\n       original_severity,\n       verdict,\n       held,\n       unattributed,\n       remediation_commits,\nevidence_explanation,\n       evidence_framework_reference,\n       evidence_original_code,\n       evidence_patched_code,\n       disposition_rationale,\n       residual_risk,\n       residual_severity,\n       cross_repo,\n       ownership,\n       business_unit,\n       tree,\n       product,\n       is_branch_audit\nFROM verification_current\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, subject_id, original_id;"

type verificationCurrentListParams struct {
	scopeIds string
}

func (q queries) verificationCurrentList(ctx context.Context, conn *sql.Conn, p verificationCurrentListParams) (*sql.Rows, error) {
	statement := verificationCurrentListSQLite
	if q.dialect == dialectPostgres {
		statement = verificationCurrentListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}

const verificationFindingUpsertPostgres = "INSERT INTO traust_storage.verification_finding (\n    binding_id,\n    artifact_digest,\n    original_id,\n    original_title,\n    original_severity,\n    verdict,\n    remediation_commits,\n    unattributed,\nevidence_explanation,\n    evidence_framework_reference,\n    evidence_original_code,\n    evidence_patched_code,\n    disposition_rationale,\n    residual_risk,\n    residual_severity,\n    cross_repo\n)\nVALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n$9,\n    $10,\n    $11,\n    $12,\n    $13,\n    $14,\n    $15,\n    $16\n)\nON CONFLICT (binding_id, original_id) DO NOTHING;"
const verificationFindingUpsertSQLite = "INSERT INTO verification_finding (\n    binding_id,\n    artifact_digest,\n    original_id,\n    original_title,\n    original_severity,\n    verdict,\n    remediation_commits,\n    unattributed,\nevidence_explanation,\n    evidence_framework_reference,\n    evidence_original_code,\n    evidence_patched_code,\n    disposition_rationale,\n    residual_risk,\n    residual_severity,\n    cross_repo\n)\nVALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id, original_id) DO NOTHING;"

type verificationFindingUpsertParams struct {
	bindingId                  string
	artifactDigest             string
	originalId                 string
	originalTitle              *string
	originalSeverity           *string
	verdict                    *string
	remediationCommits         *string
	unattributed               *int64
	evidenceExplanation        *string
	evidenceFrameworkReference *string
	evidenceOriginalCode       *string
	evidencePatchedCode        *string
	dispositionRationale       *string
	residualRisk               *string
	residualSeverity           *string
	crossRepo                  *string
}

func (q queries) verificationFindingUpsert(ctx context.Context, conn *sql.Conn, p verificationFindingUpsertParams) error {
	statement := verificationFindingUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = verificationFindingUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.originalId, p.originalTitle, p.originalSeverity, p.verdict, p.remediationCommits, p.unattributed, p.evidenceExplanation, p.evidenceFrameworkReference, p.evidenceOriginalCode, p.evidencePatchedCode, p.dispositionRationale, p.residualRisk, p.residualSeverity, p.crossRepo)
	return err
}

const verificationRegressionUpsertPostgres = "INSERT INTO traust_storage.verification_regression (\n    binding_id,\n    artifact_digest,\n    regression_id,\n    title,\n    severity,\n    cwes,\n    cvss,\n    locations,\n    description,\n    remediation,\n    evidence,\n    attack_pattern,\n    category,\n    introduced_by,\n    routed_id,\n    fingerprint,\n    fingerprint_algo\n)\nVALUES (\n    $1,\n    $2,\n    $3,\n    $4,\n    $5,\n    $6,\n    $7,\n    $8,\n    $9,\n    $10,\n    $11,\n    $12,\n    $13,\n    $14,\n    $15,\n    $16,\n    $17\n)\nON CONFLICT (binding_id, regression_id) DO NOTHING;"
const verificationRegressionUpsertSQLite = "INSERT INTO verification_regression (\n    binding_id,\n    artifact_digest,\n    regression_id,\n    title,\n    severity,\n    cwes,\n    cvss,\n    locations,\n    description,\n    remediation,\n    evidence,\n    attack_pattern,\n    category,\n    introduced_by,\n    routed_id,\n    fingerprint,\n    fingerprint_algo\n)\nVALUES (\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?,\n    ?\n)\nON CONFLICT (binding_id, regression_id) DO NOTHING;"

type verificationRegressionUpsertParams struct {
	bindingId       string
	artifactDigest  string
	regressionId    string
	title           *string
	severity        *string
	cwes            *string
	cvss            *string
	locations       *string
	description     *string
	remediation     *string
	evidence        *string
	attackPattern   *string
	category        *string
	introducedBy    *string
	routedId        *string
	fingerprint     *string
	fingerprintAlgo *string
}

func (q queries) verificationRegressionUpsert(ctx context.Context, conn *sql.Conn, p verificationRegressionUpsertParams) error {
	statement := verificationRegressionUpsertSQLite
	if q.dialect == dialectPostgres {
		statement = verificationRegressionUpsertPostgres
	}
	_, err := conn.ExecContext(ctx, statement, p.bindingId, p.artifactDigest, p.regressionId, p.title, p.severity, p.cwes, p.cvss, p.locations, p.description, p.remediation, p.evidence, p.attackPattern, p.category, p.introducedBy, p.routedId, p.fingerprint, p.fingerprintAlgo)
	return err
}

const verificationRegressionCurrentListPostgres = "SELECT scope_id,\n       subject_id,\n       run_id,\n       regression_id,\n       title,\n       severity,\n       cwes,\n       cvss,\n       locations,\n       description,\n       remediation,\n       evidence,\n       attack_pattern,\n       category,\n       introduced_by,\n       routed_id,\n       fingerprint,\n       fingerprint_algo,\n       ownership,\n       business_unit,\n       tree,\n       product,\n       is_branch_audit\nFROM traust_storage.verification_regression_current\nWHERE scope_id IN (\n    SELECT jsonb_array_elements_text($1::jsonb)\n)\nORDER BY scope_id, subject_id, regression_id;"
const verificationRegressionCurrentListSQLite = "SELECT scope_id,\n       subject_id,\n       run_id,\n       regression_id,\n       title,\n       severity,\n       cwes,\n       cvss,\n       locations,\n       description,\n       remediation,\n       evidence,\n       attack_pattern,\n       category,\n       introduced_by,\n       routed_id,\n       fingerprint,\n       fingerprint_algo,\n       ownership,\n       business_unit,\n       tree,\n       product,\n       is_branch_audit\nFROM verification_regression_current\nWHERE scope_id IN (SELECT value FROM json_each(?))\nORDER BY scope_id, subject_id, regression_id;"

type verificationRegressionCurrentListParams struct {
	scopeIds string
}

func (q queries) verificationRegressionCurrentList(ctx context.Context, conn *sql.Conn, p verificationRegressionCurrentListParams) (*sql.Rows, error) {
	statement := verificationRegressionCurrentListSQLite
	if q.dialect == dialectPostgres {
		statement = verificationRegressionCurrentListPostgres
	}
	return conn.QueryContext(ctx, statement, p.scopeIds)
}
