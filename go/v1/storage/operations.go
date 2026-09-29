// Code generated from traust-contracts 65b16f8c72159970a3aec15121601739f59867b9. DO NOT EDIT.

package storage

import (
	"context"
	"database/sql"

	"github.com/traust-security/traust-sdk/go/v1/types"
)

type SaveAdapterResultInput struct {
	Binding  Binding
	Artifact types.Artifact[types.AdapterResult]
}

func (c *Client) SaveAdapterResult(ctx context.Context, input SaveAdapterResultInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "adapter-result", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectAdapterResult)
}

func (c *Client) GetAdapterResult(ctx context.Context, bindingID string) (types.Artifact[types.AdapterResult], error) {
	return getTypedArtifact(ctx, c.store, "adapter-result", bindingID, types.ParseAdapterResultArtifact)
}

func (s *sqlStore) projectAdapterResult(ctx context.Context, conn *sql.Conn, state writeState, value types.AdapterResult) error {
	metadata, err := projectionJSON(value.Metadata)
	if err != nil {
		return projectionError(projectionAdapterResult, projectionFieldMetadata, err)
	}
	findings, err := projectionJSON(value.Findings)
	if err != nil {
		return projectionError(projectionAdapterResult, projectionFieldFindings, err)
	}
	summary, err := optionalProjectionJSON(value.Summary)
	if err != nil {
		return projectionError(projectionAdapterResult, projectionFieldSummary, err)
	}
	focusAreas, err := optionalProjectionJSON(value.FocusAreas)
	if err != nil {
		return projectionError(projectionAdapterResult, projectionFieldFocusAreas, err)
	}
	if err := s.queries.adapterResultUpsert(ctx, conn, adapterResultUpsertParams{
		bindingId:      state.bindingID,
		artifactDigest: state.digest,
		target:         value.Target,
		scannedAt:      value.ScannedAt,
		metadata:       metadata,
		findings:       findings,
		summary:        summary,
		focusAreas:     focusAreas,
	}); err != nil {
		return projectionError(projectionAdapterResult, projectionFieldRow, err)
	}
	return nil
}

type SaveADRRegistryInput struct {
	Binding  Binding
	Artifact types.Artifact[types.AdrRegistry]
}

func (c *Client) SaveADRRegistry(ctx context.Context, input SaveADRRegistryInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "adr-registry", input.Binding, bindingRequirements{subject: false, run: false, layer: false}, input.Artifact, c.store.projectADRRegistry)
}

func (c *Client) GetADRRegistry(ctx context.Context, bindingID string) (types.Artifact[types.AdrRegistry], error) {
	return getTypedArtifact(ctx, c.store, "adr-registry", bindingID, types.ParseAdrRegistryArtifact)
}

func (s *sqlStore) projectADRRegistry(ctx context.Context, conn *sql.Conn, state writeState, value types.AdrRegistry) error {
	registers, err := projectionJSON(value.Registers)
	if err != nil {
		return projectionError(projectionADRRegistry, projectionFieldRegisters, err)
	}
	if err := s.queries.adrRegistryUpsert(ctx, conn, adrRegistryUpsertParams{
		bindingId:      state.bindingID,
		artifactDigest: state.digest,
		version:        int64(value.Version),
		note:           value.Note,
		registers:      registers,
	}); err != nil {
		return projectionError(projectionADRRegistry, projectionFieldRow, err)
	}
	return nil
}

type SaveAttackMappingInput struct {
	Binding  Binding
	Artifact types.Artifact[types.AttackMapping]
}

func (c *Client) SaveAttackMapping(ctx context.Context, input SaveAttackMappingInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "attack-mapping", input.Binding, bindingRequirements{subject: false, run: false, layer: false}, input.Artifact, c.store.projectAttackMapping)
}

func (c *Client) GetAttackMapping(ctx context.Context, bindingID string) (types.Artifact[types.AttackMapping], error) {
	return getTypedArtifact(ctx, c.store, "attack-mapping", bindingID, types.ParseAttackMappingArtifact)
}

func (s *sqlStore) projectAttackMapping(ctx context.Context, conn *sql.Conn, state writeState, value types.AttackMapping) error {
	capabilityMap, err := projectionJSON(value.CapabilityMap)
	if err != nil {
		return projectionError(projectionAttackMapping, projectionFieldCapabilityMap, err)
	}
	categoryMap, err := projectionJSON(value.CategoryMap)
	if err != nil {
		return projectionError(projectionAttackMapping, projectionFieldCategoryMap, err)
	}
	if err := s.queries.attackMappingUpsert(ctx, conn, attackMappingUpsertParams{
		bindingId:      state.bindingID,
		artifactDigest: state.digest,
		mappingVersion: value.MappingVersion,
		attackVersion:  value.AttackVersion,
		source:         value.Source,
		documentation:  value.Documentation,
		schema:         value.Schema,
		attribution:    value.Attribution,
		capabilityMap:  capabilityMap,
		categoryMap:    categoryMap,
	}); err != nil {
		return projectionError(projectionAttackMapping, projectionFieldRow, err)
	}
	return nil
}

type SaveBenchmarkTargetInput struct {
	Binding  Binding
	Artifact types.Artifact[types.BenchmarkTarget]
}

func (c *Client) SaveBenchmarkTarget(ctx context.Context, input SaveBenchmarkTargetInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "benchmark-target", input.Binding, bindingRequirements{subject: false, run: false, layer: false}, input.Artifact, c.store.projectBenchmarkTarget)
}

func (c *Client) GetBenchmarkTarget(ctx context.Context, bindingID string) (types.Artifact[types.BenchmarkTarget], error) {
	return getTypedArtifact(ctx, c.store, "benchmark-target", bindingID, types.ParseBenchmarkTargetArtifact)
}

func (s *sqlStore) projectBenchmarkTarget(ctx context.Context, conn *sql.Conn, state writeState, value types.BenchmarkTarget) error {
	targets, err := projectionJSON(value.Targets)
	if err != nil {
		return projectionError(projectionBenchmarkTarget, projectionFieldTargets, err)
	}
	if err := s.queries.benchmarkTargetUpsert(ctx, conn, benchmarkTargetUpsertParams{
		bindingId:      state.bindingID,
		artifactDigest: state.digest,
		version:        int64(value.Version),
		updated:        value.Updated,
		targets:        targets,
	}); err != nil {
		return projectionError(projectionBenchmarkTarget, projectionFieldRow, err)
	}
	return nil
}

type SaveCloudConfigAuditInput struct {
	Binding  Binding
	Artifact types.Artifact[types.CloudConfigAudit]
}

func (c *Client) SaveCloudConfigAudit(ctx context.Context, input SaveCloudConfigAuditInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "cloud-config-audit", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectCloudConfigAudit)
}

func (c *Client) GetCloudConfigAudit(ctx context.Context, bindingID string) (types.Artifact[types.CloudConfigAudit], error) {
	return getTypedArtifact(ctx, c.store, "cloud-config-audit", bindingID, types.ParseCloudConfigAuditArtifact)
}

func (s *sqlStore) projectCloudConfigAudit(ctx context.Context, conn *sql.Conn, state writeState, value types.CloudConfigAudit) error {
	metadata, err := projectionJSON(value.Metadata)
	if err != nil {
		return projectionError(projectionCloudConfigAudit, projectionFieldMetadata, err)
	}
	summary, err := projectionJSON(value.Summary)
	if err != nil {
		return projectionError(projectionCloudConfigAudit, projectionFieldSummary, err)
	}
	findings, err := projectionJSON(value.Findings)
	if err != nil {
		return projectionError(projectionCloudConfigAudit, projectionFieldFindings, err)
	}
	gaps, err := optionalProjectionJSON(value.Gaps)
	if err != nil {
		return projectionError(projectionCloudConfigAudit, projectionFieldGaps, err)
	}
	if err := s.queries.cloudConfigAuditUpsert(ctx, conn, cloudConfigAuditUpsertParams{
		bindingId:      state.bindingID,
		artifactDigest: state.digest,
		title:          value.Title,
		metadata:       metadata,
		summary:        summary,
		findings:       findings,
		gaps:           gaps,
	}); err != nil {
		return projectionError(projectionCloudConfigAudit, projectionFieldRow, err)
	}
	return nil
}

type SaveCloudConfigFindingsCurrentInput struct {
	Binding  Binding
	Artifact types.Artifact[types.CloudConfigFindingsCurrent]
}

func (c *Client) SaveCloudConfigFindingsCurrent(ctx context.Context, input SaveCloudConfigFindingsCurrentInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "cloud-config-findings-current", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectCloudConfigFindingsCurrent)
}

func (c *Client) GetCloudConfigFindingsCurrent(ctx context.Context, bindingID string) (types.Artifact[types.CloudConfigFindingsCurrent], error) {
	return getTypedArtifact(ctx, c.store, "cloud-config-findings-current", bindingID, types.ParseCloudConfigFindingsCurrentArtifact)
}

func (s *sqlStore) projectCloudConfigFindingsCurrent(ctx context.Context, conn *sql.Conn, state writeState, value types.CloudConfigFindingsCurrent) error {
	metadata, err := projectionJSON(value.Metadata)
	if err != nil {
		return projectionError(projectionCloudConfigFindingsCurrent, projectionFieldMetadata, err)
	}
	summary, err := projectionJSON(value.Summary)
	if err != nil {
		return projectionError(projectionCloudConfigFindingsCurrent, projectionFieldSummary, err)
	}
	findings, err := projectionJSON(value.Findings)
	if err != nil {
		return projectionError(projectionCloudConfigFindingsCurrent, projectionFieldFindings, err)
	}
	gaps, err := optionalProjectionJSON(value.Gaps)
	if err != nil {
		return projectionError(projectionCloudConfigFindingsCurrent, projectionFieldGaps, err)
	}
	dispositionSummary, err := projectionJSON(value.DispositionSummary)
	if err != nil {
		return projectionError(projectionCloudConfigFindingsCurrent, projectionFieldDispositionSummary, err)
	}
	if err := s.queries.cloudConfigFindingsCurrentUpsert(ctx, conn, cloudConfigFindingsCurrentUpsertParams{
		bindingId:          state.bindingID,
		artifactDigest:     state.digest,
		title:              value.Title,
		metadata:           metadata,
		summary:            summary,
		findings:           findings,
		gaps:               gaps,
		dispositionSummary: dispositionSummary,
	}); err != nil {
		return projectionError(projectionCloudConfigFindingsCurrent, projectionFieldRow, err)
	}
	return nil
}

type SaveComplianceAssessmentInput struct {
	Binding  Binding
	Artifact types.Artifact[types.ComplianceAssessment]
}

func (c *Client) SaveComplianceAssessment(ctx context.Context, input SaveComplianceAssessmentInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "compliance-assessment", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectComplianceAssessment)
}

func (c *Client) GetComplianceAssessment(ctx context.Context, bindingID string) (types.Artifact[types.ComplianceAssessment], error) {
	return getTypedArtifact(ctx, c.store, "compliance-assessment", bindingID, types.ParseComplianceAssessmentArtifact)
}

func (s *sqlStore) projectComplianceAssessment(ctx context.Context, conn *sql.Conn, state writeState, value types.ComplianceAssessment) error {
	metadata, err := projectionJSON(value.Metadata)
	if err != nil {
		return projectionError(projectionComplianceAssessment, projectionFieldMetadata, err)
	}
	coverage, err := projectionJSON(value.Coverage)
	if err != nil {
		return projectionError(projectionComplianceAssessment, projectionFieldCoverage, err)
	}
	results, err := projectionJSON(value.Results)
	if err != nil {
		return projectionError(projectionComplianceAssessment, projectionFieldResults, err)
	}
	if err := s.queries.complianceAssessmentUpsert(ctx, conn, complianceAssessmentUpsertParams{
		bindingId:      state.bindingID,
		artifactDigest: state.digest,
		metadata:       metadata,
		coverage:       coverage,
		results:        results,
	}); err != nil {
		return projectionError(projectionComplianceAssessment, projectionFieldRow, err)
	}
	return nil
}

type SaveComplianceMappingInput struct {
	Binding  Binding
	Artifact types.Artifact[types.ComplianceMapping]
}

func (c *Client) SaveComplianceMapping(ctx context.Context, input SaveComplianceMappingInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "compliance-mapping", input.Binding, bindingRequirements{subject: false, run: false, layer: false}, input.Artifact, c.store.projectComplianceMapping)
}

func (c *Client) GetComplianceMapping(ctx context.Context, bindingID string) (types.Artifact[types.ComplianceMapping], error) {
	return getTypedArtifact(ctx, c.store, "compliance-mapping", bindingID, types.ParseComplianceMappingArtifact)
}

func (s *sqlStore) projectComplianceMapping(ctx context.Context, conn *sql.Conn, state writeState, value types.ComplianceMapping) error {
	controls, err := projectionJSON(value.Controls)
	if err != nil {
		return projectionError(projectionComplianceMapping, projectionFieldControls, err)
	}
	checks, err := projectionJSON(value.Checks)
	if err != nil {
		return projectionError(projectionComplianceMapping, projectionFieldChecks, err)
	}
	if err := s.queries.complianceMappingUpsert(ctx, conn, complianceMappingUpsertParams{
		bindingId:      state.bindingID,
		artifactDigest: state.digest,
		version:        int64(value.Version),
		note:           value.Note,
		controls:       controls,
		checks:         checks,
	}); err != nil {
		return projectionError(projectionComplianceMapping, projectionFieldRow, err)
	}
	return nil
}

type SaveComplianceScopeInput struct {
	Binding  Binding
	Artifact types.Artifact[types.ComplianceScope]
}

func (c *Client) SaveComplianceScope(ctx context.Context, input SaveComplianceScopeInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "compliance-scope", input.Binding, bindingRequirements{subject: false, run: false, layer: false}, input.Artifact, c.store.projectComplianceScope)
}

func (c *Client) GetComplianceScope(ctx context.Context, bindingID string) (types.Artifact[types.ComplianceScope], error) {
	return getTypedArtifact(ctx, c.store, "compliance-scope", bindingID, types.ParseComplianceScopeArtifact)
}

func (s *sqlStore) projectComplianceScope(ctx context.Context, conn *sql.Conn, state writeState, value types.ComplianceScope) error {
	boundaries, err := projectionJSON(value.Boundaries)
	if err != nil {
		return projectionError(projectionComplianceScope, projectionFieldBoundaries, err)
	}
	if err := s.queries.complianceScopeUpsert(ctx, conn, complianceScopeUpsertParams{
		bindingId:      state.bindingID,
		artifactDigest: state.digest,
		version:        int64(value.Version),
		updated:        value.Updated,
		boundaries:     boundaries,
	}); err != nil {
		return projectionError(projectionComplianceScope, projectionFieldRow, err)
	}
	return nil
}

type SaveCorpusRegistryInput struct {
	Binding  Binding
	Artifact types.Artifact[types.CorpusRegistry]
}

func (c *Client) SaveCorpusRegistry(ctx context.Context, input SaveCorpusRegistryInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "corpus-registry", input.Binding, bindingRequirements{subject: false, run: false, layer: false}, input.Artifact, c.store.projectCorpusRegistry)
}

func (c *Client) GetCorpusRegistry(ctx context.Context, bindingID string) (types.Artifact[types.CorpusRegistry], error) {
	return getTypedArtifact(ctx, c.store, "corpus-registry", bindingID, types.ParseCorpusRegistryArtifact)
}

type SaveDocVarianceInput struct {
	Binding  Binding
	Artifact types.Artifact[types.DocVariance]
}

func (c *Client) SaveDocVariance(ctx context.Context, input SaveDocVarianceInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "doc-variance", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectDocVariance)
}

func (c *Client) GetDocVariance(ctx context.Context, bindingID string) (types.Artifact[types.DocVariance], error) {
	return getTypedArtifact(ctx, c.store, "doc-variance", bindingID, types.ParseDocVarianceArtifact)
}

func (s *sqlStore) projectDocVariance(ctx context.Context, conn *sql.Conn, state writeState, value types.DocVariance) error {
	metadata, err := projectionJSON(value.Metadata)
	if err != nil {
		return projectionError(projectionDocVariance, projectionFieldMetadata, err)
	}
	records, err := projectionJSON(value.Records)
	if err != nil {
		return projectionError(projectionDocVariance, projectionFieldRecords, err)
	}
	if err := s.queries.docVarianceUpsert(ctx, conn, docVarianceUpsertParams{
		bindingId:      state.bindingID,
		artifactDigest: state.digest,
		metadata:       metadata,
		records:        records,
	}); err != nil {
		return projectionError(projectionDocVariance, projectionFieldRow, err)
	}
	return nil
}

type SaveFleetFixInput struct {
	Binding  Binding
	Artifact types.Artifact[types.FleetFix]
}

func (c *Client) SaveFleetFix(ctx context.Context, input SaveFleetFixInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "fleet-fix", input.Binding, bindingRequirements{subject: false, run: false, layer: false}, input.Artifact, c.store.projectFleetFix)
}

func (c *Client) GetFleetFix(ctx context.Context, bindingID string) (types.Artifact[types.FleetFix], error) {
	return getTypedArtifact(ctx, c.store, "fleet-fix", bindingID, types.ParseFleetFixArtifact)
}

func (s *sqlStore) projectFleetFix(ctx context.Context, conn *sql.Conn, state writeState, value types.FleetFix) error {
	matcher, err := projectionJSON(value.Matcher)
	if err != nil {
		return projectionError(projectionFleetFix, projectionFieldMatcher, err)
	}
	resolver, err := optionalProjectionJSON(value.Resolver)
	if err != nil {
		return projectionError(projectionFleetFix, projectionFieldResolver, err)
	}
	rewrite, err := projectionJSON(value.Rewrite)
	if err != nil {
		return projectionError(projectionFleetFix, projectionFieldRewrite, err)
	}
	guards, err := projectionJSON(value.Guards)
	if err != nil {
		return projectionError(projectionFleetFix, projectionFieldGuards, err)
	}
	tests, err := projectionJSON(value.Tests)
	if err != nil {
		return projectionError(projectionFleetFix, projectionFieldTests, err)
	}
	if err := s.queries.fleetFixUpsert(ctx, conn, fleetFixUpsertParams{
		bindingId:      state.bindingID,
		artifactDigest: state.digest,
		id:             value.Id,
		patternRef:     value.PatternRef,
		description:    value.Description,
		matcher:        matcher,
		resolver:       resolver,
		rewrite:        rewrite,
		guards:         guards,
		tests:          tests,
	}); err != nil {
		return projectionError(projectionFleetFix, projectionFieldRow, err)
	}
	return nil
}

type SaveImpactAnalysisInput struct {
	Binding  Binding
	Artifact types.Artifact[types.ImpactAnalysis]
}

func (c *Client) SaveImpactAnalysis(ctx context.Context, input SaveImpactAnalysisInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "impact-analysis", input.Binding, bindingRequirements{subject: false, run: false, layer: false}, input.Artifact, c.store.projectImpactAnalysis)
}

func (c *Client) GetImpactAnalysis(ctx context.Context, bindingID string) (types.Artifact[types.ImpactAnalysis], error) {
	return getTypedArtifact(ctx, c.store, "impact-analysis", bindingID, types.ParseImpactAnalysisArtifact)
}

func (s *sqlStore) projectImpactAnalysis(ctx context.Context, conn *sql.Conn, state writeState, value types.ImpactAnalysis) error {
	metadata, err := projectionJSON(value.Metadata)
	if err != nil {
		return projectionError(projectionImpactAnalysis, projectionFieldMetadata, err)
	}
	summary, err := projectionJSON(value.Summary)
	if err != nil {
		return projectionError(projectionImpactAnalysis, projectionFieldSummary, err)
	}
	repos, err := projectionJSON(value.Repos)
	if err != nil {
		return projectionError(projectionImpactAnalysis, projectionFieldRepos, err)
	}
	if err := s.queries.impactAnalysisUpsert(ctx, conn, impactAnalysisUpsertParams{
		bindingId:      state.bindingID,
		artifactDigest: state.digest,
		metadata:       metadata,
		summary:        summary,
		repos:          repos,
	}); err != nil {
		return projectionError(projectionImpactAnalysis, projectionFieldRow, err)
	}
	return nil
}

type SaveIsolationReviewInput struct {
	Binding  Binding
	Artifact types.Artifact[types.IsolationReview]
}

func (c *Client) SaveIsolationReview(ctx context.Context, input SaveIsolationReviewInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "isolation-review", input.Binding, bindingRequirements{subject: false, run: false, layer: false}, input.Artifact, c.store.projectIsolationReview)
}

func (c *Client) GetIsolationReview(ctx context.Context, bindingID string) (types.Artifact[types.IsolationReview], error) {
	return getTypedArtifact(ctx, c.store, "isolation-review", bindingID, types.ParseIsolationReviewArtifact)
}

func (s *sqlStore) projectIsolationReview(ctx context.Context, conn *sql.Conn, state writeState, value types.IsolationReview) error {
	metadata, err := projectionJSON(value.Metadata)
	if err != nil {
		return projectionError(projectionIsolationReview, projectionFieldMetadata, err)
	}
	interfaces, err := projectionJSON(value.Interfaces)
	if err != nil {
		return projectionError(projectionIsolationReview, projectionFieldInterfaces, err)
	}
	gaps, err := projectionJSON(value.Gaps)
	if err != nil {
		return projectionError(projectionIsolationReview, projectionFieldGaps, err)
	}
	posture, err := projectionJSON(value.Posture)
	if err != nil {
		return projectionError(projectionIsolationReview, projectionFieldPosture, err)
	}
	if err := s.queries.isolationReviewUpsert(ctx, conn, isolationReviewUpsertParams{
		bindingId:      state.bindingID,
		artifactDigest: state.digest,
		title:          value.Title,
		metadata:       metadata,
		interfaces:     interfaces,
		gaps:           gaps,
		posture:        posture,
		notes:          value.Notes,
	}); err != nil {
		return projectionError(projectionIsolationReview, projectionFieldRow, err)
	}
	return nil
}

type SaveLayerInput struct {
	Binding  Binding
	Artifact types.Artifact[types.Layer]
}

func (c *Client) SaveLayer(ctx context.Context, input SaveLayerInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "layer", input.Binding, bindingRequirements{subject: false, run: false, layer: true}, input.Artifact, c.store.projectLayer)
}

func (c *Client) GetLayer(ctx context.Context, bindingID string) (types.Artifact[types.Layer], error) {
	return getTypedArtifact(ctx, c.store, "layer", bindingID, types.ParseLayerArtifact)
}

type SaveOperatorPrivProfileInput struct {
	Binding  Binding
	Artifact types.Artifact[types.OperatorPrivProfile]
}

func (c *Client) SaveOperatorPrivProfile(ctx context.Context, input SaveOperatorPrivProfileInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "operator-priv-profile", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectOperatorPrivProfile)
}

func (c *Client) GetOperatorPrivProfile(ctx context.Context, bindingID string) (types.Artifact[types.OperatorPrivProfile], error) {
	return getTypedArtifact(ctx, c.store, "operator-priv-profile", bindingID, types.ParseOperatorPrivProfileArtifact)
}

func (s *sqlStore) projectOperatorPrivProfile(ctx context.Context, conn *sql.Conn, state writeState, value types.OperatorPrivProfile) error {
	workloads, err := optionalProjectionJSON(value.Workloads)
	if err != nil {
		return projectionError(projectionPrivProfile, projectionFieldWorkloads, err)
	}
	rbacRules, err := optionalProjectionJSON(value.RbacRules)
	if err != nil {
		return projectionError(projectionPrivProfile, projectionFieldRbacRules, err)
	}
	rbacFlags, err := optionalProjectionJSON(value.RbacFlags)
	if err != nil {
		return projectionError(projectionPrivProfile, projectionFieldRbacFlags, err)
	}
	sccRequests, err := optionalProjectionJSON(value.SccRequests)
	if err != nil {
		return projectionError(projectionPrivProfile, projectionFieldSccRequests, err)
	}
	sccsShipped, err := optionalProjectionJSON(value.SccsShipped)
	if err != nil {
		return projectionError(projectionPrivProfile, projectionFieldSccsShipped, err)
	}
	namespaces, err := optionalProjectionJSON(value.Namespaces)
	if err != nil {
		return projectionError(projectionPrivProfile, projectionFieldNamespaces, err)
	}
	installModes, err := optionalProjectionJSON(value.InstallModes)
	if err != nil {
		return projectionError(projectionPrivProfile, projectionFieldInstallModes, err)
	}
	operatorgroups, err := optionalProjectionJSON(value.Operatorgroups)
	if err != nil {
		return projectionError(projectionPrivProfile, projectionFieldOperatorgroups, err)
	}
	tier2RequiredVsGranted, err := optionalProjectionJSON(value.Tier2RequiredVsGranted)
	if err != nil {
		return projectionError(projectionPrivProfile, projectionFieldTier2RequiredVsGranted, err)
	}
	exampleOrTestManifestsExcluded, err := optionalProjectionJSON(value.ExampleOrTestManifestsExcluded)
	if err != nil {
		return projectionError(projectionPrivProfile, projectionFieldExampleOrTestManifestsExcluded, err)
	}
	summary, err := optionalProjectionJSON(value.Summary)
	if err != nil {
		return projectionError(projectionPrivProfile, projectionFieldSummary, err)
	}
	if err := s.queries.privProfileUpsert(ctx, conn, privProfileUpsertParams{
		bindingId:                      state.bindingID,
		artifactDigest:                 state.digest,
		repo:                           value.Repo,
		tier:                           value.Tier,
		workloads:                      workloads,
		rbacRules:                      rbacRules,
		rbacFlags:                      rbacFlags,
		sccRequests:                    sccRequests,
		sccsShipped:                    sccsShipped,
		namespaces:                     namespaces,
		installModes:                   installModes,
		operatorgroups:                 operatorgroups,
		tier2RequiredVsGranted:         tier2RequiredVsGranted,
		exampleOrTestManifestsExcluded: exampleOrTestManifestsExcluded,
		summary:                        summary,
	}); err != nil {
		return projectionError(projectionPrivProfile, projectionFieldRow, err)
	}
	return nil
}

type SaveOrgParametersInput struct {
	Binding  Binding
	Artifact types.Artifact[types.OrgParameters]
}

func (c *Client) SaveOrgParameters(ctx context.Context, input SaveOrgParametersInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "org-parameters", input.Binding, bindingRequirements{subject: false, run: false, layer: false}, input.Artifact, c.store.projectOrgParameters)
}

func (c *Client) GetOrgParameters(ctx context.Context, bindingID string) (types.Artifact[types.OrgParameters], error) {
	return getTypedArtifact(ctx, c.store, "org-parameters", bindingID, types.ParseOrgParametersArtifact)
}

func (s *sqlStore) projectOrgParameters(ctx context.Context, conn *sql.Conn, state writeState, value types.OrgParameters) error {
	parameters, err := projectionJSON(value.Parameters)
	if err != nil {
		return projectionError(projectionOrgParameters, projectionFieldParameters, err)
	}
	if err := s.queries.orgParametersUpsert(ctx, conn, orgParametersUpsertParams{
		bindingId:      state.bindingID,
		artifactDigest: state.digest,
		version:        int64(value.Version),
		declaredBy:     value.DeclaredBy,
		declaredOn:     value.DeclaredOn,
		note:           value.Note,
		parameters:     parameters,
	}); err != nil {
		return projectionError(projectionOrgParameters, projectionFieldRow, err)
	}
	return nil
}

type SavePQCBlockersInput struct {
	Binding  Binding
	Artifact types.Artifact[types.PqcBlockers]
}

func (c *Client) SavePQCBlockers(ctx context.Context, input SavePQCBlockersInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "pqc-blockers", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectPQCBlockers)
}

func (c *Client) GetPQCBlockers(ctx context.Context, bindingID string) (types.Artifact[types.PqcBlockers], error) {
	return getTypedArtifact(ctx, c.store, "pqc-blockers", bindingID, types.ParsePqcBlockersArtifact)
}

func (s *sqlStore) projectPQCBlockers(ctx context.Context, conn *sql.Conn, state writeState, value types.PqcBlockers) error {
	artifact, err := projectionText(value.Artifact)
	if err != nil {
		return projectionError(projectionPQCBlockers, projectionFieldArtifact, err)
	}
	metadata, err := projectionJSON(value.Metadata)
	if err != nil {
		return projectionError(projectionPQCBlockers, projectionFieldMetadata, err)
	}
	executiveSummary, err := projectionJSON(value.ExecutiveSummary)
	if err != nil {
		return projectionError(projectionPQCBlockers, projectionFieldExecutiveSummary, err)
	}
	severityCriteria, err := projectionJSON(value.SeverityCriteria)
	if err != nil {
		return projectionError(projectionPQCBlockers, projectionFieldSeverityCriteria, err)
	}
	findings, err := projectionJSON(value.Findings)
	if err != nil {
		return projectionError(projectionPQCBlockers, projectionFieldFindings, err)
	}
	findingsSummary, err := projectionJSON(value.FindingsSummary)
	if err != nil {
		return projectionError(projectionPQCBlockers, projectionFieldFindingsSummary, err)
	}
	remediationRoadmap, err := projectionJSON(value.RemediationRoadmap)
	if err != nil {
		return projectionError(projectionPQCBlockers, projectionFieldRemediationRoadmap, err)
	}
	if err := s.queries.pqcBlockersUpsert(ctx, conn, pqcBlockersUpsertParams{
		bindingId:          state.bindingID,
		artifactDigest:     state.digest,
		artifact:           artifact,
		title:              value.Title,
		metadata:           metadata,
		executiveSummary:   executiveSummary,
		severityCriteria:   severityCriteria,
		findings:           findings,
		findingsSummary:    findingsSummary,
		remediationRoadmap: remediationRoadmap,
	}); err != nil {
		return projectionError(projectionPQCBlockers, projectionFieldRow, err)
	}
	return nil
}

type SavePQCDecisionTreeInput struct {
	Binding  Binding
	Artifact types.Artifact[types.PqcDecisionTree]
}

func (c *Client) SavePQCDecisionTree(ctx context.Context, input SavePQCDecisionTreeInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "pqc-decision-tree", input.Binding, bindingRequirements{subject: false, run: false, layer: false}, input.Artifact, c.store.projectPQCDecisionTree)
}

func (c *Client) GetPQCDecisionTree(ctx context.Context, bindingID string) (types.Artifact[types.PqcDecisionTree], error) {
	return getTypedArtifact(ctx, c.store, "pqc-decision-tree", bindingID, types.ParsePqcDecisionTreeArtifact)
}

func (s *sqlStore) projectPQCDecisionTree(ctx context.Context, conn *sql.Conn, state writeState, value types.PqcDecisionTree) error {
	provenanceTree, err := projectionJSON(value.ProvenanceTree)
	if err != nil {
		return projectionError(projectionPQCDecisionTree, projectionFieldProvenanceTree, err)
	}
	remediationEffort, err := projectionJSON(value.RemediationEffort)
	if err != nil {
		return projectionError(projectionPQCDecisionTree, projectionFieldRemediationEffort, err)
	}
	readinessBuckets, err := projectionJSON(value.ReadinessBuckets)
	if err != nil {
		return projectionError(projectionPQCDecisionTree, projectionFieldReadinessBuckets, err)
	}
	tlsControlCrosswalk, err := projectionJSON(value.TlsControlCrosswalk)
	if err != nil {
		return projectionError(projectionPQCDecisionTree, projectionFieldTlsControlCrosswalk, err)
	}
	fipsInteraction, err := projectionJSON(value.FipsInteraction)
	if err != nil {
		return projectionError(projectionPQCDecisionTree, projectionFieldFipsInteraction, err)
	}
	pqcClassificationMap, err := projectionJSON(value.PqcClassificationMap)
	if err != nil {
		return projectionError(projectionPQCDecisionTree, projectionFieldPQCClassificationMap, err)
	}
	serverSideCaveat, err := optionalProjectionJSON(value.ServerSideCaveat)
	if err != nil {
		return projectionError(projectionPQCDecisionTree, projectionFieldServerSideCaveat, err)
	}
	if err := s.queries.pqcDecisionTreeUpsert(ctx, conn, pqcDecisionTreeUpsertParams{
		bindingId:            state.bindingID,
		artifactDigest:       state.digest,
		treeVersion:          value.TreeVersion,
		plan:                 value.Plan,
		schema:               value.Schema,
		provenanceTree:       provenanceTree,
		remediationEffort:    remediationEffort,
		readinessBuckets:     readinessBuckets,
		tlsControlCrosswalk:  tlsControlCrosswalk,
		fipsInteraction:      fipsInteraction,
		pqcClassificationMap: pqcClassificationMap,
		serverSideCaveat:     serverSideCaveat,
	}); err != nil {
		return projectionError(projectionPQCDecisionTree, projectionFieldRow, err)
	}
	return nil
}

type SavePQCFactsInput struct {
	Binding  Binding
	Artifact types.Artifact[types.PqcFacts]
}

func (c *Client) SavePQCFacts(ctx context.Context, input SavePQCFactsInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "pqc-facts", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectPQCFacts)
}

func (c *Client) GetPQCFacts(ctx context.Context, bindingID string) (types.Artifact[types.PqcFacts], error) {
	return getTypedArtifact(ctx, c.store, "pqc-facts", bindingID, types.ParsePqcFactsArtifact)
}

func (s *sqlStore) projectPQCFacts(ctx context.Context, conn *sql.Conn, state writeState, value types.PqcFacts) error {
	artifact, err := projectionText(value.Artifact)
	if err != nil {
		return projectionError(projectionPQCFacts, projectionFieldArtifact, err)
	}
	stamps, err := projectionJSON(value.Stamps)
	if err != nil {
		return projectionError(projectionPQCFacts, projectionFieldStamps, err)
	}
	coverage, err := projectionJSON(value.Coverage)
	if err != nil {
		return projectionError(projectionPQCFacts, projectionFieldCoverage, err)
	}
	summary, err := projectionJSON(value.Summary)
	if err != nil {
		return projectionError(projectionPQCFacts, projectionFieldSummary, err)
	}
	facts, err := projectionJSON(value.Facts)
	if err != nil {
		return projectionError(projectionPQCFacts, projectionFieldFacts, err)
	}
	if err := s.queries.pqcFactsUpsert(ctx, conn, pqcFactsUpsertParams{
		bindingId:      state.bindingID,
		artifactDigest: state.digest,
		artifact:       artifact,
		repository:     value.Repository,
		stamps:         stamps,
		coverage:       coverage,
		summary:        summary,
		facts:          facts,
	}); err != nil {
		return projectionError(projectionPQCFacts, projectionFieldRow, err)
	}
	return nil
}

type SavePQCReadinessInput struct {
	Binding  Binding
	Artifact types.Artifact[types.PqcReadiness]
}

func (c *Client) SavePQCReadiness(ctx context.Context, input SavePQCReadinessInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "pqc-readiness", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectPQCReadiness)
}

func (c *Client) GetPQCReadiness(ctx context.Context, bindingID string) (types.Artifact[types.PqcReadiness], error) {
	return getTypedArtifact(ctx, c.store, "pqc-readiness", bindingID, types.ParsePqcReadinessArtifact)
}

func (s *sqlStore) projectPQCReadiness(ctx context.Context, conn *sql.Conn, state writeState, value types.PqcReadiness) error {
	metadata, err := projectionJSON(value.Metadata)
	if err != nil {
		return projectionError(projectionPQCReadiness, projectionFieldMetadata, err)
	}
	scores, err := projectionJSON(value.Scores)
	if err != nil {
		return projectionError(projectionPQCReadiness, projectionFieldScores, err)
	}
	flags, err := projectionJSON(value.Flags)
	if err != nil {
		return projectionError(projectionPQCReadiness, projectionFieldFlags, err)
	}
	provenanceSummary, err := projectionJSON(value.ProvenanceSummary)
	if err != nil {
		return projectionError(projectionPQCReadiness, projectionFieldProvenanceSummary, err)
	}
	clockItems, err := optionalProjectionJSON(value.ClockItems)
	if err != nil {
		return projectionError(projectionPQCReadiness, projectionFieldClockItems, err)
	}
	fipsInteraction, err := optionalProjectionJSON(value.FipsInteraction)
	if err != nil {
		return projectionError(projectionPQCReadiness, projectionFieldFipsInteraction, err)
	}
	runtimeEvidence, err := optionalProjectionJSON(value.RuntimeEvidence)
	if err != nil {
		return projectionError(projectionPQCReadiness, projectionFieldRuntimeEvidence, err)
	}
	serverSideCaveats, err := optionalProjectionJSON(value.ServerSideCaveats)
	if err != nil {
		return projectionError(projectionPQCReadiness, projectionFieldServerSideCaveats, err)
	}
	remediations, err := optionalProjectionJSON(value.Remediations)
	if err != nil {
		return projectionError(projectionPQCReadiness, projectionFieldRemediations, err)
	}
	if err := s.queries.pqcReadinessUpsert(ctx, conn, pqcReadinessUpsertParams{
		bindingId:         state.bindingID,
		artifactDigest:    state.digest,
		title:             value.Title,
		metadata:          metadata,
		scores:            scores,
		flags:             flags,
		provenanceSummary: provenanceSummary,
		clockItems:        clockItems,
		readinessBucket:   projectionEnum(value.ReadinessBucket),
		fipsInteraction:   fipsInteraction,
		runtimeEvidence:   runtimeEvidence,
		serverSideCaveats: serverSideCaveats,
		notes:             value.Notes,
		remediations:      remediations,
	}); err != nil {
		return projectionError(projectionPQCReadiness, projectionFieldRow, err)
	}
	return nil
}

type SaveRefutedRegisterInput struct {
	Binding  Binding
	Artifact types.Artifact[types.RefutedRegister]
}

func (c *Client) SaveRefutedRegister(ctx context.Context, input SaveRefutedRegisterInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "refuted-register", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectRefutedRegister)
}

func (c *Client) GetRefutedRegister(ctx context.Context, bindingID string) (types.Artifact[types.RefutedRegister], error) {
	return getTypedArtifact(ctx, c.store, "refuted-register", bindingID, types.ParseRefutedRegisterArtifact)
}

func (s *sqlStore) projectRefutedRegister(ctx context.Context, conn *sql.Conn, state writeState, value types.RefutedRegister) error {
	sources, err := optionalProjectionJSON(value.Sources)
	if err != nil {
		return projectionError(projectionRefutedRegister, projectionFieldSources, err)
	}
	entries, err := projectionJSON(value.Entries)
	if err != nil {
		return projectionError(projectionRefutedRegister, projectionFieldEntries, err)
	}
	if err := s.queries.refutedRegisterUpsert(ctx, conn, refutedRegisterUpsertParams{
		bindingId:      state.bindingID,
		artifactDigest: state.digest,
		source:         value.Source,
		sources:        sources,
		generatedAt:    value.GeneratedAt,
		entries:        entries,
	}); err != nil {
		return projectionError(projectionRefutedRegister, projectionFieldRow, err)
	}
	return nil
}

type SaveRemediationInput struct {
	Binding  Binding
	Artifact types.Artifact[types.Remediation]
}

func (c *Client) SaveRemediation(ctx context.Context, input SaveRemediationInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "remediation", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectRemediation)
}

func (c *Client) GetRemediation(ctx context.Context, bindingID string) (types.Artifact[types.Remediation], error) {
	return getTypedArtifact(ctx, c.store, "remediation", bindingID, types.ParseRemediationArtifact)
}

func (s *sqlStore) projectRemediation(ctx context.Context, conn *sql.Conn, state writeState, value types.Remediation) error {
	metadata, err := projectionJSON(value.Metadata)
	if err != nil {
		return projectionError(projectionRemediation, projectionFieldMetadata, err)
	}
	sourceFindings, err := projectionJSON(value.SourceFindings)
	if err != nil {
		return projectionError(projectionRemediation, projectionFieldSourceFindings, err)
	}
	fork, err := projectionJSON(value.Fork)
	if err != nil {
		return projectionError(projectionRemediation, projectionFieldFork, err)
	}
	patch, err := projectionJSON(value.Patch)
	if err != nil {
		return projectionError(projectionRemediation, projectionFieldPatch, err)
	}
	checks, err := projectionJSON(value.Checks)
	if err != nil {
		return projectionError(projectionRemediation, projectionFieldChecks, err)
	}
	evidence, err := optionalProjectionJSON(value.Evidence)
	if err != nil {
		return projectionError(projectionRemediation, projectionFieldEvidence, err)
	}
	revalidation, err := optionalProjectionJSON(value.Revalidation)
	if err != nil {
		return projectionError(projectionRemediation, projectionFieldRevalidation, err)
	}
	pullRequest, err := optionalProjectionJSON(value.PullRequest)
	if err != nil {
		return projectionError(projectionRemediation, projectionFieldPullRequest, err)
	}
	summary, err := projectionJSON(value.Summary)
	if err != nil {
		return projectionError(projectionRemediation, projectionFieldSummary, err)
	}
	if err := s.queries.remediationUpsert(ctx, conn, remediationUpsertParams{
		bindingId:      state.bindingID,
		artifactDigest: state.digest,
		title:          value.Title,
		metadata:       metadata,
		sourceFindings: sourceFindings,
		fork:           fork,
		patch:          patch,
		checks:         checks,
		evidence:       evidence,
		revalidation:   revalidation,
		pullRequest:    pullRequest,
		summary:        summary,
		notes:          value.Notes,
		footer:         value.Footer,
	}); err != nil {
		return projectionError(projectionRemediation, projectionFieldRow, err)
	}
	return nil
}

type SaveReportInput struct {
	Binding  Binding
	Artifact types.Artifact[types.Report]
}

func (c *Client) SaveReport(ctx context.Context, input SaveReportInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "report", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectReport)
}

func (c *Client) GetReport(ctx context.Context, bindingID string) (types.Artifact[types.Report], error) {
	return getTypedArtifact(ctx, c.store, "report", bindingID, types.ParseReportArtifact)
}

func (s *sqlStore) projectReport(ctx context.Context, conn *sql.Conn, state writeState, value types.Report) error {
	metadata, err := projectionJSON(value.Metadata)
	if err != nil {
		return projectionError(projectionReport, projectionFieldMetadata, err)
	}
	executiveSummary, err := projectionJSON(value.ExecutiveSummary)
	if err != nil {
		return projectionError(projectionReport, projectionFieldExecutiveSummary, err)
	}
	severityCriteria, err := projectionJSON(value.SeverityCriteria)
	if err != nil {
		return projectionError(projectionReport, projectionFieldSeverityCriteria, err)
	}
	findings, err := projectionJSON(value.Findings)
	if err != nil {
		return projectionError(projectionReport, projectionFieldFindings, err)
	}
	findingsSummary, err := projectionJSON(value.FindingsSummary)
	if err != nil {
		return projectionError(projectionReport, projectionFieldFindingsSummary, err)
	}
	remediationRoadmap, err := projectionJSON(value.RemediationRoadmap)
	if err != nil {
		return projectionError(projectionReport, projectionFieldRemediationRoadmap, err)
	}
	dependencyAudit, err := optionalProjectionJSON(value.DependencyAudit)
	if err != nil {
		return projectionError(projectionReport, projectionFieldDependencyAudit, err)
	}
	negativeResults, err := optionalProjectionJSON(value.NegativeResults)
	if err != nil {
		return projectionError(projectionReport, projectionFieldNegativeResults, err)
	}
	asvsCoverage, err := optionalProjectionJSON(value.AsvsCoverage)
	if err != nil {
		return projectionError(projectionReport, projectionFieldAsvsCoverage, err)
	}
	scannerCorrelation, err := optionalProjectionJSON(value.ScannerCorrelation)
	if err != nil {
		return projectionError(projectionReport, projectionFieldScannerCorrelation, err)
	}
	peachIsolationReview, err := optionalProjectionJSON(value.PeachIsolationReview)
	if err != nil {
		return projectionError(projectionReport, projectionFieldPeachIsolationReview, err)
	}
	dispositionSummary, err := optionalProjectionJSON(value.DispositionSummary)
	if err != nil {
		return projectionError(projectionReport, projectionFieldDispositionSummary, err)
	}
	if err := s.queries.reportUpsert(ctx, conn, reportUpsertParams{
		bindingId:            state.bindingID,
		artifactDigest:       state.digest,
		title:                value.Title,
		metadata:             metadata,
		executiveSummary:     executiveSummary,
		severityCriteria:     severityCriteria,
		findings:             findings,
		findingsSummary:      findingsSummary,
		remediationRoadmap:   remediationRoadmap,
		dependencyAudit:      dependencyAudit,
		negativeResults:      negativeResults,
		asvsCoverage:         asvsCoverage,
		scannerCorrelation:   scannerCorrelation,
		peachIsolationReview: peachIsolationReview,
		dispositionSummary:   dispositionSummary,
		footer:               value.Footer,
	}); err != nil {
		return projectionError(projectionReport, projectionFieldRow, err)
	}
	return s.projectReportFindings(ctx, conn, state, value)
}

type SaveRiskRatingMethodologyInput struct {
	Binding  Binding
	Artifact types.Artifact[types.RiskRatingMethodology]
}

func (c *Client) SaveRiskRatingMethodology(ctx context.Context, input SaveRiskRatingMethodologyInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "risk-rating-methodology", input.Binding, bindingRequirements{subject: false, run: false, layer: false}, input.Artifact, c.store.projectRiskRatingMethodology)
}

func (c *Client) GetRiskRatingMethodology(ctx context.Context, bindingID string) (types.Artifact[types.RiskRatingMethodology], error) {
	return getTypedArtifact(ctx, c.store, "risk-rating-methodology", bindingID, types.ParseRiskRatingMethodologyArtifact)
}

func (s *sqlStore) projectRiskRatingMethodology(ctx context.Context, conn *sql.Conn, state writeState, value types.RiskRatingMethodology) error {
	methodology, err := projectionText(value.Methodology)
	if err != nil {
		return projectionError(projectionRiskRatingMethodology, projectionFieldMethodology, err)
	}
	bands, err := projectionJSON(value.Bands)
	if err != nil {
		return projectionError(projectionRiskRatingMethodology, projectionFieldBands, err)
	}
	bucketThresholds, err := projectionJSON(value.BucketThresholds)
	if err != nil {
		return projectionError(projectionRiskRatingMethodology, projectionFieldBucketThresholds, err)
	}
	likelihoodFactors, err := projectionJSON(value.LikelihoodFactors)
	if err != nil {
		return projectionError(projectionRiskRatingMethodology, projectionFieldLikelihoodFactors, err)
	}
	impactFactors, err := projectionJSON(value.ImpactFactors)
	if err != nil {
		return projectionError(projectionRiskRatingMethodology, projectionFieldImpactFactors, err)
	}
	matrix, err := projectionJSON(value.Matrix)
	if err != nil {
		return projectionError(projectionRiskRatingMethodology, projectionFieldMatrix, err)
	}
	fallback, err := projectionJSON(value.Fallback)
	if err != nil {
		return projectionError(projectionRiskRatingMethodology, projectionFieldFallback, err)
	}
	threatIntelFactor, err := optionalProjectionJSON(value.ThreatIntelFactor)
	if err != nil {
		return projectionError(projectionRiskRatingMethodology, projectionFieldThreatIntelFactor, err)
	}
	if err := s.queries.riskRatingMethodologyUpsert(ctx, conn, riskRatingMethodologyUpsertParams{
		bindingId:          state.bindingID,
		artifactDigest:     state.digest,
		methodology:        methodology,
		methodologyVersion: value.MethodologyVersion,
		source:             value.Source,
		documentation:      value.Documentation,
		schema:             value.Schema,
		bands:              bands,
		bucketThresholds:   bucketThresholds,
		likelihoodFactors:  likelihoodFactors,
		impactFactors:      impactFactors,
		matrix:             matrix,
		fallback:           fallback,
		threatIntelFactor:  threatIntelFactor,
	}); err != nil {
		return projectionError(projectionRiskRatingMethodology, projectionFieldRow, err)
	}
	return nil
}

type SaveSlaPolicyInput struct {
	Binding  Binding
	Artifact types.Artifact[types.SlaPolicy]
}

func (c *Client) SaveSlaPolicy(ctx context.Context, input SaveSlaPolicyInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "sla-policy", input.Binding, bindingRequirements{subject: false, run: false, layer: false}, input.Artifact, c.store.projectSlaPolicy)
}

func (c *Client) GetSlaPolicy(ctx context.Context, bindingID string) (types.Artifact[types.SlaPolicy], error) {
	return getTypedArtifact(ctx, c.store, "sla-policy", bindingID, types.ParseSlaPolicyArtifact)
}

func (s *sqlStore) projectSlaPolicy(ctx context.Context, conn *sql.Conn, state writeState, value types.SlaPolicy) error {
	source, err := projectionJSON(value.Source)
	if err != nil {
		return projectionError(projectionSlaPolicy, projectionFieldSource, err)
	}
	severityMapping, err := projectionJSON(value.SeverityMapping)
	if err != nil {
		return projectionError(projectionSlaPolicy, projectionFieldSeverityMapping, err)
	}
	profiles, err := projectionJSON(value.Profiles)
	if err != nil {
		return projectionError(projectionSlaPolicy, projectionFieldProfiles, err)
	}
	if err := s.queries.slaPolicyUpsert(ctx, conn, slaPolicyUpsertParams{
		bindingId:       state.bindingID,
		artifactDigest:  state.digest,
		policyName:      value.PolicyName,
		source:          source,
		severityMapping: severityMapping,
		clockStart:      projectionEnum(value.ClockStart),
		profiles:        profiles,
	}); err != nil {
		return projectionError(projectionSlaPolicy, projectionFieldRow, err)
	}
	return nil
}

type SaveThreatModelInput struct {
	Binding  Binding
	Artifact types.Artifact[types.ThreatModel]
}

func (c *Client) SaveThreatModel(ctx context.Context, input SaveThreatModelInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "threat-model", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectThreatModel)
}

func (c *Client) GetThreatModel(ctx context.Context, bindingID string) (types.Artifact[types.ThreatModel], error) {
	return getTypedArtifact(ctx, c.store, "threat-model", bindingID, types.ParseThreatModelArtifact)
}

type SaveTriageInput struct {
	Binding  Binding
	Artifact types.Artifact[types.Triage]
}

func (c *Client) SaveTriage(ctx context.Context, input SaveTriageInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "triage", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectTriage)
}

func (c *Client) GetTriage(ctx context.Context, bindingID string) (types.Artifact[types.Triage], error) {
	return getTypedArtifact(ctx, c.store, "triage", bindingID, types.ParseTriageArtifact)
}

type SaveValidationInput struct {
	Binding  Binding
	Artifact types.Artifact[types.Validation]
}

func (c *Client) SaveValidation(ctx context.Context, input SaveValidationInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "validation", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectValidation)
}

func (c *Client) GetValidation(ctx context.Context, bindingID string) (types.Artifact[types.Validation], error) {
	return getTypedArtifact(ctx, c.store, "validation", bindingID, types.ParseValidationArtifact)
}

func (s *sqlStore) projectValidation(ctx context.Context, conn *sql.Conn, state writeState, value types.Validation) error {
	metadata, err := projectionJSON(value.Metadata)
	if err != nil {
		return projectionError(projectionValidation, projectionFieldMetadata, err)
	}
	sourceReports, err := projectionJSON(value.SourceReports)
	if err != nil {
		return projectionError(projectionValidation, projectionFieldSourceReports, err)
	}
	summary, err := projectionJSON(value.Summary)
	if err != nil {
		return projectionError(projectionValidation, projectionFieldSummary, err)
	}
	validatedFindings, err := projectionJSON(value.ValidatedFindings)
	if err != nil {
		return projectionError(projectionValidation, projectionFieldValidatedFindings, err)
	}
	attackChains, err := projectionJSON(value.AttackChains)
	if err != nil {
		return projectionError(projectionValidation, projectionFieldAttackChains, err)
	}
	novelFindings, err := projectionJSON(value.NovelFindings)
	if err != nil {
		return projectionError(projectionValidation, projectionFieldNovelFindings, err)
	}
	negativeResults, err := optionalProjectionJSON(value.NegativeResults)
	if err != nil {
		return projectionError(projectionValidation, projectionFieldNegativeResults, err)
	}
	if err := s.queries.validationUpsert(ctx, conn, validationUpsertParams{
		bindingId:          state.bindingID,
		artifactDigest:     state.digest,
		title:              value.Title,
		metadata:           metadata,
		sourceReports:      sourceReports,
		summary:            summary,
		validatedFindings:  validatedFindings,
		attackChains:       attackChains,
		novelFindings:      novelFindings,
		negativeResults:    negativeResults,
		executionLogRef:    value.ExecutionLogRef,
		executionLogSha256: value.ExecutionLogSha256,
		footer:             value.Footer,
	}); err != nil {
		return projectionError(projectionValidation, projectionFieldRow, err)
	}
	return nil
}

type SaveVerificationInput struct {
	Binding  Binding
	Artifact types.Artifact[types.Verification]
}

func (c *Client) SaveVerification(ctx context.Context, input SaveVerificationInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "verification", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectVerification)
}

func (c *Client) GetVerification(ctx context.Context, bindingID string) (types.Artifact[types.Verification], error) {
	return getTypedArtifact(ctx, c.store, "verification", bindingID, types.ParseVerificationArtifact)
}

func (s *sqlStore) projectVerification(ctx context.Context, conn *sql.Conn, state writeState, value types.Verification) error {
	metadata, err := projectionJSON(value.Metadata)
	if err != nil {
		return projectionError(projectionVerification, projectionFieldMetadata, err)
	}
	summary, err := projectionJSON(value.Summary)
	if err != nil {
		return projectionError(projectionVerification, projectionFieldSummary, err)
	}
	verifiedFindings, err := projectionJSON(value.VerifiedFindings)
	if err != nil {
		return projectionError(projectionVerification, projectionFieldVerifiedFindings, err)
	}
	regressions, err := projectionJSON(value.Regressions)
	if err != nil {
		return projectionError(projectionVerification, projectionFieldRegressions, err)
	}
	commitTimeline, err := projectionJSON(value.CommitTimeline)
	if err != nil {
		return projectionError(projectionVerification, projectionFieldCommitTimeline, err)
	}
	evidence, err := optionalProjectionJSON(value.Evidence)
	if err != nil {
		return projectionError(projectionVerification, projectionFieldEvidence, err)
	}
	recommendations, err := optionalProjectionJSON(value.Recommendations)
	if err != nil {
		return projectionError(projectionVerification, projectionFieldRecommendations, err)
	}
	if err := s.queries.verificationUpsert(ctx, conn, verificationUpsertParams{
		bindingId:        state.bindingID,
		artifactDigest:   state.digest,
		title:            value.Title,
		metadata:         metadata,
		summary:          summary,
		verifiedFindings: verifiedFindings,
		regressions:      regressions,
		commitTimeline:   commitTimeline,
		evidence:         evidence,
		recommendations:  recommendations,
		notes:            value.Notes,
		footer:           value.Footer,
	}); err != nil {
		return projectionError(projectionVerification, projectionFieldRow, err)
	}
	return nil
}

type SaveVulnFindingsInput struct {
	Binding  Binding
	Artifact types.Artifact[types.VulnFindings]
}

func (c *Client) SaveVulnFindings(ctx context.Context, input SaveVulnFindingsInput) (SaveResult, error) {
	return saveTypedArtifact(ctx, c.store, "vuln-findings", input.Binding, bindingRequirements{subject: true, run: true, layer: false}, input.Artifact, c.store.projectVulnFindings)
}

func (c *Client) GetVulnFindings(ctx context.Context, bindingID string) (types.Artifact[types.VulnFindings], error) {
	return getTypedArtifact(ctx, c.store, "vuln-findings", bindingID, types.ParseVulnFindingsArtifact)
}

func (c *Client) saveNamed(ctx context.Context, name string, payload []byte, binding Binding) (SaveResult, error) {
	switch name {
	case "adapter-result":
		artifact, err := types.ParseAdapterResultArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveAdapterResult(ctx, SaveAdapterResultInput{Binding: binding, Artifact: artifact})
	case "adr-registry":
		artifact, err := types.ParseAdrRegistryArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveADRRegistry(ctx, SaveADRRegistryInput{Binding: binding, Artifact: artifact})
	case "attack-mapping":
		artifact, err := types.ParseAttackMappingArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveAttackMapping(ctx, SaveAttackMappingInput{Binding: binding, Artifact: artifact})
	case "benchmark-target":
		artifact, err := types.ParseBenchmarkTargetArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveBenchmarkTarget(ctx, SaveBenchmarkTargetInput{Binding: binding, Artifact: artifact})
	case "cloud-config-audit":
		artifact, err := types.ParseCloudConfigAuditArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveCloudConfigAudit(ctx, SaveCloudConfigAuditInput{Binding: binding, Artifact: artifact})
	case "cloud-config-findings-current":
		artifact, err := types.ParseCloudConfigFindingsCurrentArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveCloudConfigFindingsCurrent(ctx, SaveCloudConfigFindingsCurrentInput{Binding: binding, Artifact: artifact})
	case "compliance-assessment":
		artifact, err := types.ParseComplianceAssessmentArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveComplianceAssessment(ctx, SaveComplianceAssessmentInput{Binding: binding, Artifact: artifact})
	case "compliance-mapping":
		artifact, err := types.ParseComplianceMappingArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveComplianceMapping(ctx, SaveComplianceMappingInput{Binding: binding, Artifact: artifact})
	case "compliance-scope":
		artifact, err := types.ParseComplianceScopeArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveComplianceScope(ctx, SaveComplianceScopeInput{Binding: binding, Artifact: artifact})
	case "corpus-registry":
		artifact, err := types.ParseCorpusRegistryArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveCorpusRegistry(ctx, SaveCorpusRegistryInput{Binding: binding, Artifact: artifact})
	case "doc-variance":
		artifact, err := types.ParseDocVarianceArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveDocVariance(ctx, SaveDocVarianceInput{Binding: binding, Artifact: artifact})
	case "fleet-fix":
		artifact, err := types.ParseFleetFixArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveFleetFix(ctx, SaveFleetFixInput{Binding: binding, Artifact: artifact})
	case "impact-analysis":
		artifact, err := types.ParseImpactAnalysisArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveImpactAnalysis(ctx, SaveImpactAnalysisInput{Binding: binding, Artifact: artifact})
	case "isolation-review":
		artifact, err := types.ParseIsolationReviewArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveIsolationReview(ctx, SaveIsolationReviewInput{Binding: binding, Artifact: artifact})
	case "layer":
		artifact, err := types.ParseLayerArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveLayer(ctx, SaveLayerInput{Binding: binding, Artifact: artifact})
	case "operator-priv-profile":
		artifact, err := types.ParseOperatorPrivProfileArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveOperatorPrivProfile(ctx, SaveOperatorPrivProfileInput{Binding: binding, Artifact: artifact})
	case "org-parameters":
		artifact, err := types.ParseOrgParametersArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveOrgParameters(ctx, SaveOrgParametersInput{Binding: binding, Artifact: artifact})
	case "pqc-blockers":
		artifact, err := types.ParsePqcBlockersArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SavePQCBlockers(ctx, SavePQCBlockersInput{Binding: binding, Artifact: artifact})
	case "pqc-decision-tree":
		artifact, err := types.ParsePqcDecisionTreeArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SavePQCDecisionTree(ctx, SavePQCDecisionTreeInput{Binding: binding, Artifact: artifact})
	case "pqc-facts":
		artifact, err := types.ParsePqcFactsArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SavePQCFacts(ctx, SavePQCFactsInput{Binding: binding, Artifact: artifact})
	case "pqc-readiness":
		artifact, err := types.ParsePqcReadinessArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SavePQCReadiness(ctx, SavePQCReadinessInput{Binding: binding, Artifact: artifact})
	case "refuted-register":
		artifact, err := types.ParseRefutedRegisterArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveRefutedRegister(ctx, SaveRefutedRegisterInput{Binding: binding, Artifact: artifact})
	case "remediation":
		artifact, err := types.ParseRemediationArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveRemediation(ctx, SaveRemediationInput{Binding: binding, Artifact: artifact})
	case "report":
		artifact, err := types.ParseReportArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveReport(ctx, SaveReportInput{Binding: binding, Artifact: artifact})
	case "risk-rating-methodology":
		artifact, err := types.ParseRiskRatingMethodologyArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveRiskRatingMethodology(ctx, SaveRiskRatingMethodologyInput{Binding: binding, Artifact: artifact})
	case "sla-policy":
		artifact, err := types.ParseSlaPolicyArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveSlaPolicy(ctx, SaveSlaPolicyInput{Binding: binding, Artifact: artifact})
	case "threat-model":
		artifact, err := types.ParseThreatModelArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveThreatModel(ctx, SaveThreatModelInput{Binding: binding, Artifact: artifact})
	case "triage":
		artifact, err := types.ParseTriageArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveTriage(ctx, SaveTriageInput{Binding: binding, Artifact: artifact})
	case "validation":
		artifact, err := types.ParseValidationArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveValidation(ctx, SaveValidationInput{Binding: binding, Artifact: artifact})
	case "verification":
		artifact, err := types.ParseVerificationArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveVerification(ctx, SaveVerificationInput{Binding: binding, Artifact: artifact})
	case "vuln-findings":
		artifact, err := types.ParseVulnFindingsArtifact(payload)
		if err != nil {
			return SaveResult{}, wrap(OperationSave, PhaseValidate, err)
		}
		return c.SaveVulnFindings(ctx, SaveVulnFindingsInput{Binding: binding, Artifact: artifact})
	default:
		return SaveResult{}, wrap(OperationSave, PhaseInput, ErrUnknownArtifact)
	}
}
