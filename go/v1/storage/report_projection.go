package storage

import (
	"context"
	"database/sql"

	"github.com/traust-security/traust-sdk/go/v1/types"
)

func projectionEnum[Enum ~string](value *Enum) *string {
	if value == nil {
		return nil
	}
	converted := string(*value)
	return &converted
}

func (s *sqlStore) projectReportFindings(ctx context.Context, conn *sql.Conn, state writeState, report types.Report) error {
	for index, finding := range report.Findings {
		severity := string(finding.Severity)
		params := reportFindingUpsertParams{
			bindingId: state.bindingID, artifactDigest: state.digest, findingId: finding.Id,
			title: &finding.Title, severity: &severity, fingerprint: finding.Fingerprint,
			validationStatus: projectionEnum(finding.ValidationStatus),
			description:      &finding.Description, remediation: &finding.Remediation,
			category: finding.Category, attackPattern: finding.AttackPattern,
			effectiveSeverity: projectionEnum(finding.EffectiveSeverity),
			origin:            projectionEnum(finding.Origin),
			remediationEffort: projectionEnum(finding.RemediationEffort),
			pqcClassification: projectionEnum(finding.PqcClassification),
			fingerprintAlgo:   finding.FingerprintAlgo, isolationBoundary: finding.IsolationBoundary,
		}
		var override any
		if disposition := finding.Disposition; disposition != nil {
			validity, resolution := string(disposition.Validity), string(disposition.Resolution)
			params.validity, params.resolution = &validity, &resolution
			params.assurance = projectionEnum(disposition.Assurance)
			params.lastUpdated = &disposition.LastUpdated
			params.conflict = optionalBoolAsInt(disposition.Conflict)
			params.fpOverridden = optionalBoolAsInt(disposition.FpOverridden)
			params.fpReassertionBlocked = optionalBoolAsInt(disposition.FpReassertionBlocked)
			params.refutedAwaitingSignoff = optionalBoolAsInt(disposition.RefutedAwaitingSignoff)
			override = disposition.SeverityOverride
		}
		for _, field := range []struct {
			name   projectionField
			value  any
			target **string
		}{
			{"severity_override", override, &params.severityOverride},
			{"cwes", finding.Cwes, &params.cwes},
			{"locations", finding.Locations, &params.locations},
			{"asvs_references", finding.AsvsReferences, &params.asvsReferences},
			{"peach_references", finding.PeachReferences, &params.peachReferences},
			{"capec", finding.Capec, &params.capec},
			{"cvss", finding.Cvss, &params.cvss},
			{"evidence", finding.Evidence, &params.evidence},
			{"source_findings", finding.SourceFindings, &params.sourceFindings},
			{"passes", finding.Passes, &params.passes},
			{"isolation_dimensions", finding.IsolationDimensions, &params.isolationDimensions},
			{"dependency", finding.Dependency, &params.dependency},
		} {
			encoded, err := optionalProjectionJSON(field.value)
			if err != nil {
				return projectionError(projectionReportFinding, indexedProjectionField(field.name, index), err)
			}
			*field.target = encoded
		}
		if err := s.queries.reportFindingUpsert(ctx, conn, params); err != nil {
			return projectionError(projectionReportFinding, indexedProjectionField(projectionFieldRow, index), err)
		}
	}
	return nil
}
