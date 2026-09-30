// Package storage records v1 artifact evidence and binds it to caller-owned context.
//
// Callers own the database pool and the preprocessing boundary. PostgreSQL
// relations use the fixed traust_storage schema; SQLite uses the caller-selected
// database file as its physical namespace. Each named Save operation validates
// a raw-preserving generated artifact, records the sha256 digest and byte size
// of the exact bytes supplied to Save, creates an opaque scope/subject/run/layer
// binding, and writes any approved projection in one transaction. storage/v1
// does not retain the bytes themselves. Optional enrichment,
// including Ledger fingerprint stamping, happens before Save; storage neither
// computes nor promotes that enrichment as independent authority.
//
// Typed Get operations and GetEvidence resolve a binding but return
// ErrArtifactBytesNotRetained, because no bytes are retained. Every artifact
// has a schema-specific SQL projection. Consumers correlate Ledger disposition
// data through the caller-supplied layer ID and artifact-relative finding ID;
// fingerprints remain payload evidence or Ledger-owned state, not storage join
// keys. Stored strings remain untrusted when rendered and require
// context-appropriate output encoding.
package storage
