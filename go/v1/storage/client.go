package storage

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
)

const (
	storageFormatVersion   = "v1"
	contractRevision       = 2
	minimumPostgresVersion = 140000
)

type Client struct {
	store *sqlStore
}

type dialect uint8

const (
	dialectSQLite dialect = iota
	dialectPostgres
)

type sqlStore struct {
	db       *sql.DB
	dialect  dialect
	queries  queries
	resolver Resolver
}

// Option configures a Client.
type Option func(*sqlStore)

// WithResolver lets typed Get operations fetch artifact bytes from the
// references registered at Save. Register-only callers need no resolver.
func WithResolver(resolver Resolver) Option {
	return func(s *sqlStore) { s.resolver = resolver }
}

// NewClient binds storage to a caller-owned database pool.
func NewClient(ctx context.Context, db *sql.DB, opts ...Option) (*Client, error) {
	if db == nil {
		return nil, wrap(OperationInit, PhaseInput, ErrNilDatabase)
	}
	store := &sqlStore{db: db}
	for _, opt := range opts {
		opt(store)
	}
	if isNilInterface(store.resolver) {
		store.resolver = nil
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, wrap(OperationInit, PhaseConnect, err)
	}
	defer func() { _ = conn.Close() }()

	dialect, err := detectDialect(ctx, conn)
	if err != nil {
		return nil, err
	}
	store.dialect = dialect
	store.queries = queries{dialect: dialect}
	return &Client{store: store}, nil
}

// isNilInterface treats a typed nil (e.g. a nil *MyResolver) as no resolver,
// so Get fails with ErrNoResolver instead of panicking inside Fetch.
func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// Init creates storage in an empty database or verifies its exact revision.
func (c *Client) Init(ctx context.Context) error {
	if c == nil || c.store == nil {
		return wrap(OperationInit, PhaseInput, ErrNilDatabase)
	}
	return c.store.init(ctx)
}

func detectDialect(ctx context.Context, conn *sql.Conn) (dialect, error) {
	var postgresVersion int
	if err := conn.QueryRowContext(ctx, "SHOW server_version_num").Scan(&postgresVersion); err == nil {
		if postgresVersion < minimumPostgresVersion {
			return 0, wrap(OperationInit, PhaseDialect, ErrIncompatibleDatabase)
		}
		return dialectPostgres, nil
	}

	var sqliteVersion string
	if err := conn.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&sqliteVersion); err == nil {
		return dialectSQLite, nil
	}
	return 0, wrap(OperationInit, PhaseDialect, ErrUnsupportedDatabase)
}

func (s *sqlStore) init(ctx context.Context) (err error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return wrap(OperationInit, PhaseConnect, err)
	}
	defer func() { _ = conn.Close() }()

	if err = s.prepareConnection(ctx, conn); err != nil {
		return wrap(OperationInit, PhaseConnect, err)
	}
	if err = begin(ctx, conn, s.dialect); err != nil {
		return wrap(OperationInit, PhaseBegin, err)
	}
	committed := false
	defer rollbackUnlessCommitted(ctx, conn, &committed)

	if s.dialect == dialectPostgres {
		if err = s.queries.traustStorageMetaLock(ctx, conn, traustStorageMetaLockParams{}); err != nil {
			return wrap(OperationInit, PhaseLock, err)
		}
	}

	exists, err := s.storageMetadataExists(ctx, conn)
	if err != nil {
		return err
	}
	if exists {
		err = s.requireStorageRevision(ctx, conn)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	if !exists || errors.Is(err, sql.ErrNoRows) {
		if err = s.bootstrap(ctx, conn); err != nil {
			return err
		}
	}

	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return wrap(OperationInit, PhaseCommit, err)
	}
	committed = true
	return nil
}

func (s *sqlStore) storageMetadataExists(ctx context.Context, conn *sql.Conn) (bool, error) {
	var relation any
	err := s.queries.traustStorageMetaExists(ctx, conn, traustStorageMetaExistsParams{}).Scan(&relation)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, wrap(OperationInit, PhaseRevision, err)
	}
	return relation != nil, nil
}

func (s *sqlStore) requireStorageRevision(ctx context.Context, conn *sql.Conn) error {
	var version string
	var revision int
	if err := s.queries.traustStorageMetaGet(ctx, conn, traustStorageMetaGetParams{}).Scan(&version, &revision); err != nil {
		return wrap(OperationInit, PhaseRevision, err)
	}
	if version != storageFormatVersion || revision != contractRevision {
		return wrap(OperationInit, PhaseRevision, ErrIncompatibleRevision)
	}
	return nil
}

func (s *sqlStore) bootstrap(ctx context.Context, conn *sql.Conn) error {
	for _, statement := range generatedBootstrap(s.dialect) {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return wrap(OperationInit, PhaseBootstrap, err)
		}
	}
	if err := s.queries.traustStorageMetaUpsert(ctx, conn, traustStorageMetaUpsertParams{
		contractVersion: storageFormatVersion,
		revision:        contractRevision,
		appliedAt:       nowUTC(),
	}); err != nil {
		return wrap(OperationInit, PhaseRevision, err)
	}
	return nil
}
