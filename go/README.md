# traust-sdk (Go)

```bash
go get github.com/traust-security/traust-sdk/go@latest
```

Consumer setup is three handles, with no traust tables or types of your own:

| Need | Package | You supply |
|---|---|---|
| Store and read traust artifacts | [`v1/storage`](#storage-sdk) | `*sql.DB` + `storage.ObjectStore`; `Init` bootstraps the contracts DDL in `traust_storage` |
| Dispositions, events, countersign | [`v1/ledger`](#ledger-sdk) | ledger URL + token |
| Run skills | [`v1/skills`](#skills-sdk) | a `skills.Provider` |

Keep consumer tables for consumer data only and reference traust rows by `binding_id` / `layer_id`. Overview: [../README.md → Purpose](../README.md#purpose).

## Skills SDK

Import a skill, plug in your provider, call it — typed input in, typed result out:

```go
import "github.com/traust-security/traust-sdk/go/v1/skills"

provider := myK8sProvider(...)  // you implement skills.Provider

artifact, err := skills.Scan.Run(ctx, provider, skills.ScanInput{
    Repo: "https://github.com/org/repo",
    Ref:  "main",
})
report, err := artifact.Value()
if err != nil {
    return err
}
for _, finding := range report.Findings {
    fmt.Println(finding.Id, finding.Severity, finding.Title)
}
```

`skills.Provider` is the only interface you implement — it runs a skill somewhere
(K8s Job, Docker, local subprocess, ...) and returns raw bytes:

```go
type Provider interface {
    Execute(ctx context.Context, skill SkillMeta, input []byte) ([]byte, error)
}
```

The SDK validates the response and retains its exact bytes with the generated
Go type. `Artifact.Value` decodes typed data; `Artifact.Payload` returns owned,
byte-identical evidence suitable for storage or export.

### Calling multiple skills

Bind the provider once with a Client:

```go
client := skills.NewClient(provider)
report, _ := client.Scan(ctx, skills.ScanInput{...})
triage, _ := client.Triage(ctx, skills.TriageInput{...})
```

### Testing

```go
import "github.com/traust-security/traust-sdk/go/v1/skills/skillstest"

provider := skillstest.NewStaticProvider().
    WithScanResult(skillstest.FixtureReport())

report, _ := skills.Scan.Run(ctx, provider, skills.ScanInput{
    Repo: "https://github.com/org/repo",
    Ref:  "main",
})
```

## Ledger SDK

Submit reports and human events to the ledger service:

```go
import "github.com/traust-security/traust-sdk/go/v1/ledger"

client := ledger.NewHTTPClient("https://ledger.example.com",
    ledger.WithBearerToken(os.Getenv("LEDGER_TOKEN")),
)

// Machine lane — triage report (derives disposition events)
resp, err := client.SubmitTriageReport(ctx, ledger.TriageReportInput{
    ReportMeta: ledger.ReportMeta{
        LayerID:    "repo-a",
        SourceRef:  "findings/repo-a/triage.json",
        RecordedAt: time.Now().UTC().Format(time.RFC3339),
    },
    Report: triageReport,
})

// Human lane — countersign
resp, err = client.SubmitCountersign(ctx, ledger.CountersignInput{
    EventMeta: ledger.EventMeta{
        LayerID:    "repo-a",
        RecordedAt: time.Now().UTC().Format(time.RFC3339),
    },
    FindingRef:    "FIND-001",
    Verdict:       "true_positive",
    Justification: "Reviewed source and confirmed exploit path.",
})

// Sign a layer's merkle tree
signResp, err := client.SignLayer(ctx, "repo-a", ledger.SignOpts{})
```

Machine-lane report kinds: `triage`, `validation`. Human-lane event kinds:
`countersign`, `severity`. Additional operations: `BatchSubmit`,
`ResolveReviewItem`, `ComputeFingerprints`, `StampEventIdentities`, and
`SignLayer`.

The built-in HTTP transport handles envelope formatting, lane routing, and auth.
For custom transports, implement `ledger.Provider` and use `ledger.NewClient(provider)`.

### Testing

```go
import "github.com/traust-security/traust-sdk/go/v1/ledger/ingesttest"

provider := ingesttest.NewStaticProvider().
    WithTriageResponse(ingesttest.FixtureTriageResponse())
client := ledger.NewClient(provider)
```

## Query SDK

Read layers, findings, and verification results from the ledger service:

```go
import "github.com/traust-security/traust-sdk/go/v1/ledger"

client := ledger.NewHTTPClient("https://ledger.example.com",
    ledger.WithBearerToken(os.Getenv("LEDGER_TOKEN")),
)

// Read resolved findings for a layer
findings, err := client.GetFindings(ctx, "repo-a")
// Paginated bulk findings
page, err := client.ListFindings(ctx, ledger.ListFindingsOpts{Limit: 50})
// Verify layer integrity
result, err := client.VerifyLayer(ctx, "repo-a", ledger.VerifyOpts{CheckSignatures: true})
// Resolve the authenticated actor without recording an event
actor, err := client.Whoami(ctx)
```

The built-in HTTP transport handles auth and path construction.
For custom transports, implement `ledger.Provider` and use `ledger.NewClient(provider)`.

### Testing

```go
import "github.com/traust-security/traust-sdk/go/v1/ledger/querytest"

provider := querytest.NewStaticProvider().
    WithFindingsResponse("repo-a", querytest.FixtureFindingsResponse())
client := ledger.NewClient(provider)
```

## Storage SDK

Storage retains exact artifact evidence and its canonical relational projection in
one SQLite or PostgreSQL transaction. PostgreSQL relations use the fixed
`traust_storage` schema so application tables and `search_path` cannot redirect
storage operations. SQLite uses the caller-selected database file as its physical
namespace; a dedicated file is recommended. The caller owns the driver, DSN, pool
settings, health checks, and database closure:

```go
import (
    "database/sql"

    _ "github.com/jackc/pgx/v5/stdlib"
    "github.com/traust-security/traust-sdk/go/v1/storage"
)

db, err := sql.Open("pgx", dsn)
if err != nil {
    return err
}
defer db.Close()

// objects implements storage.ObjectStore; supply an S3, GCS, or directory
// adapter from your application, or storagetest.MemoryStore in tests.
client, err := storage.NewClient(ctx, db, objects)
if err != nil {
    return err
}
if err = client.Init(ctx); err != nil {
    return err
}
subjectID := "myapp:subject:" + subjectKey
runID := "myapp:run:" + runKey
result, err := client.SaveVulnFindings(ctx, storage.SaveVulnFindingsInput{
    Binding: storage.Binding{
        ScopeID:   "local",
        SubjectID: &subjectID,
        RunID:     &runID,
    },
    Artifact: artifact,
})
```

Every schema has named typed save and read operations. A named save validates the
source bytes, computes their SHA-256 digest, records globally deduplicated
`artifact_evidence` (digest and byte size), and creates a context-specific
`artifact_binding` and projection in one SQL transaction. The required external
`storage.ObjectStore` stores bytes by SHA-256 digest before that transaction, so
failed database writes can leave unreferenced objects but never dangling bindings.
A nil store fails construction with `storage.ErrNilObjectStore`. Typed reads
and `GetEvidence` verify the returned bytes against the recorded size and digest;
missing objects return `storage.ErrNotFound`. `storage.ObjectKey(prefix, digest)`
returns a digest-addressed path, and `storagetest.MemoryStore` supports tests
without a bucket. Store implementations live in consumers, not in the SDK.
`SaveResult.AlreadyBound` reports only whether that binding existed; evidence-level
deduplication remains private. Orphan cleanup must first check active bindings.

The exact-evidence boundary is the named Save call. Callers may perform optional
processing, such as asking Ledger to stamp finding fingerprints, before creating
the artifact passed to storage. Storage records the digest of those accepted bytes
but does not compute fingerprints or treat them as storage-owned identity. When Ledger is
present, consumers join disposition data by the binding's `layer_id` and the
artifact-relative finding ID; fingerprints remain report evidence or
Ledger-owned state rather than storage join keys.

Every artifact contract has a schema-specific SQL projection. Root fields become
typed columns while nested values remain JSON until a query justifies child tables.
Scoped views exercise cross-artifact binding relationships; all projections retain
generated save and smoke-test coverage. Run-bound saves require caller-supplied
subject and run IDs; layer saves require a Ledger layer ID. Identifiers are opaque
UTF-8 strings, and omitted scope defaults to `local`.

Typed reads use `BindingID` to guard the stored schema interpretation. Use
`GetEvidence(ctx, digest)` only when raw bytes without a type claim are intended.
Scoped view reads require an explicit scope list.

## Data-only usage

For consumers who just need types or validation without invoking skills:

| Package | Contents |
|---|---|
| [`v1/types`](v1/types) | Generated Go structs for every schema in `schemas/v1` |
| [`v1/enums`](v1/enums) | Generated shared vocabularies (severity, validity, verdicts, ...) |
| [`v1/validate`](v1/validate) | Validate raw JSON bytes against an embedded v1 schema |

## Regenerating types/enums/validate/storage

```bash
make generate     # verified pinned contracts commit → generated Go outputs
make check-drift  # fails if generated output is stale
```

No sibling checkout is needed. `make generate` obtains the full immutable
`CONTRACTS_REF` from `CONTRACTS_REPO` and validates that the checkout matches it
exactly; it never generates from latest `main`. The checkout is reused from
`CONTRACTS_CACHE` (by default the user cache) at `CONTRACTS_SOURCE`. All four
variables are caller-overridable for fork, CI-cache, and pinned-ref workflows.
Normal `make test` uses only repository fixtures and requires no network.

Run `make test-integration` for the storage suite against SQLite and PostgreSQL.
The PostgreSQL suite uses one fixed local test DSN, recreates `traust_storage`
for each test, and verifies that same-named application tables remain untouched.
Start the database with:

```bash
podman run --name traust-postgres --rm -d -e POSTGRES_USER=traust -e POSTGRES_PASSWORD=traust-test-only -e POSTGRES_DB=traust_test -p 127.0.0.1:5432:5432 -v traust-postgres-data:/var/lib/postgresql/data docker.io/library/postgres:16
```

These are fixed local test-only credentials, **not production/deployed secrets**,
and no DSN override is supported. `make test-integration` disables the Go test cache so PostgreSQL availability is
checked on every run. PostgreSQL absence, connectivity failure, or authentication
failure produces a visible skip while SQLite still executes. Once PostgreSQL
accepts a connection, all version, initialization, and protocol failures fail.
