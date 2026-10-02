# traust-sdk

Typed SDKs that let a consumer plug traust in without re-modeling it: storage, ledger access, skill invocation, and generated types/validation.

## Purpose

The SDK's primary goal is **plug-and-play consumption**. A consumer imports the SDK, points it at a database and a ledger URL, and gets traust's data model working with no tables, schemas, or identity logic of its own.

Data flows left to right: **traust data → consumer extension data**.

| Layer | Owns | Reference |
|---|---|---|
| [traust-contracts](https://github.com/traust-security/traust-contracts) | Schemas, enums, and the `traust_storage` / `traust_ledger` DDL | source of truth |
| traust-sdk (this repo) | Typed access to that data: `storage.Init` bootstraps the contracts DDL; `ledger` wraps the ledger service; `types`/`enums`/`validate` are generated | [`go/README.md`](go/README.md) |
| [traust-ledger](https://github.com/traust-security/traust-ledger) | Dispositions, countersign gates, finding identity/fingerprints | [docs/consumer-integration.md](https://github.com/traust-security/traust-ledger/blob/main/docs/consumer-integration.md) |
| Consumer | Only its own extension data (whatever its domain needs), joined to traust rows by `binding_id` / `layer_id` | the consumer's own docs |

Consumers are free to extend traust for their own use cases. When several consumers duplicate the same traust data or behavior, that's a sign it belongs in the SDK (or traust-contracts).

## Setup

```bash
make setup   # enable git hooks (once per clone)
make test              # network-free Go unit tests
make test-integration  # storage: SQLite + optional local PostgreSQL
make status            # per-language versions and tags
```

Each language has its own `{lang}/VERSION` and git tag (`{tag_prefix}/vX.Y.Z` in `ci/languages.json`).

## Language SDKs

| Language | Path | Module |
|---|---|---|
| Go | [`go/`](go/) | `github.com/traust-security/traust-sdk/go` |

## Architecture

```
traust-contracts        ← schemas, enums, DDL (source of truth)
traust-sdk              ← typed SDKs that consumers import (this repo)
consumer                ← extension data only
```

The SDK is opinionated on **contracts** (shapes, storage DDL, and ledger API come from
`traust-contracts` and `traust-ledger`) and unopinionated on **infrastructure**: the
consumer supplies the database handle, a resolver for artifact bytes it already wrote, the ledger URL and token,
and a skill `Provider` for execution.

## Regenerating from contracts

```bash
cd go/
make generate   # fetches and verifies the pinned canonical contracts commit
make test       # network-free unit tests
```

For storage integration coverage, `make test-integration` always exercises SQLite
and attempts PostgreSQL at one fixed local test DSN. Start that database with:

```bash
podman run --name traust-postgres --rm -d -e POSTGRES_USER=traust -e POSTGRES_PASSWORD=traust-test-only -e POSTGRES_DB=traust_test -p 127.0.0.1:5432:5432 -v traust-postgres-data:/var/lib/postgresql/data docker.io/library/postgres:16
```

These are fixed local test-only credentials, **not deployed credentials or
secrets**; the suite does not support a DSN override. An absent, unreachable, or
authentication-rejecting PostgreSQL skips that portion with a message. Once a
connection succeeds, Open, initialization, and protocol failures fail the test.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
