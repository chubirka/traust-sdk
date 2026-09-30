package storage

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
)

const (
	storageFormatVersion   = "v1"
	contractRevision       = 1
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
	db      *sql.DB
	dialect dialect
	queries queries
	objects ObjectStore
}

// NewClient binds storage to a caller-owned database pool and required object store.
func NewClient(ctx context.Context, db *sql.DB, objects ObjectStore) (*Client, error) {
	if db == nil {
		return nil, wrap(OperationInit, PhaseInput, ErrNilDatabase)
	}
	if objects == nil {
		return nil, wrap(OperationInit, PhaseInput, ErrNilObjectStore)
	}
	value := reflect.ValueOf(objects)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		if value.IsNil() {
			return nil, wrap(OperationInit, PhaseInput, ErrNilObjectStore)
		}
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
	return &Client{store: &sqlStore{db: db, dialect: dialect, queries: queries{dialect: dialect}, objects: objects}}, nil
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
