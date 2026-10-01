# traust-sdk

Multi-language SDKs that let consumers plug traust in: storage, ledger, skills, types/validation. Go module under `go/` today.

## Design rules

The primary goal is **plug-and-play for consumers**. Data flows left to right: traust data → consumer extension data. See [README.md → Purpose](README.md#purpose).

- **Contracts own shapes and DDL.** Generate from [traust-contracts](https://github.com/traust-security/traust-contracts); never hand-write schemas, enums, or SQL that contracts already defines. `storage.Init` bootstraps the contracts DDL so consumers create no traust tables
- **Ledger owns identity and dispositions.** Wrap the [traust-ledger](https://github.com/traust-security/traust-ledger) API; do not reimplement fingerprints, disposition derivation, or countersign gates in the SDK
- **No consumer-specific logic.** Nothing shaped for a single consumer belongs here. Consumers own infrastructure (DB handle, object store, ledger URL/token, skill `Provider`) through interfaces
- **Extend freely; upstream the repeats.** Consumers may add their own tables, types, and logic for their use cases. When a consumer duplicates traust data or behavior (a mirrored table, struct, or recipe), consider raising it as an SDK or contracts feature so it doesn't drift

## Workflow

- **Before done:** for each language you touch, run its lint + test + security targets (see table); CI enforces all configured gates

| Language | Lint | Test | Security (hard) | Generate | Packages |
|----------|------|------|-----------------|----------|----------|
| Go | `go vet`, `gofmt` (`make lint`) | `go test ./...`; storage integration: `make test-integration` | `govulncheck`, `gosec` (`make security`) | `make -C go generate` (verified pinned remote contracts commit) | go modules |

Add a row when a new SDK lands; wire matching `lint:<lang>`, `test:<lang>`, `security:<lang>` jobs under `ci/lang/`.

- **Commits:** conventional `type(scope): subject` — scope = language id when SDK-specific (e.g. `feat(go): …`)
- **Releases:** per-language `{lang}/VERSION` + `## [X.Y.Z]` in `{lang}/CHANGELOG.md`; tag `{tag_prefix}/vX.Y.Z` from `ci/languages.json`
- **CI:** per-language jobs in parallel per stage; registry in `ci/languages.json`
- **Setup:** `make setup` once per clone (hooks). More: [CONTRIBUTING.md](CONTRIBUTING.md), [README.md](README.md)
- **Generation:** no sibling checkout; `make -C go generate` obtains the full pinned `CONTRACTS_REF` from `CONTRACTS_REPO` and reuses `CONTRACTS_CACHE`/`CONTRACTS_SOURCE`. Unit tests remain network-free.
- **Storage integration:** `make test-integration` runs SQLite and attempts PostgreSQL only at the fixed local test DSN. Start it with `podman run --name traust-postgres --rm -d -e POSTGRES_USER=traust -e POSTGRES_PASSWORD=traust-test-only -e POSTGRES_DB=traust_test -p 127.0.0.1:5432:5432 -v traust-postgres-data:/var/lib/postgresql/data docker.io/library/postgres:16`. These are fixed local test-only credentials, not deployed secrets; no DSN override is supported. Connection/authentication unavailability skips PostgreSQL, but failures after connection are hard failures.
