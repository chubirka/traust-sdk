// Package s3store keeps storage/v1 artifact bytes in an S3-compatible bucket.
//
// Objects are keyed "<prefix>sha256/<digest>" (storage.ObjectKey), so any
// traust SDK can read what another wrote. Credentials are never part of
// Config: by default they are resolved from the environment (AWS_* then
// MINIO_* variables) and then from the IAM role of the running workload.
package s3store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/encrypt"

	"github.com/traust-security/traust-sdk/go/v1/storage"
)

// Encryption selects server-side encryption for written objects. The values
// are the encryption.mode values of the object-store config contract.
type Encryption string

const (
	// EncryptionBucketDefault leaves encryption to the bucket's default policy.
	// The empty string means the same.
	EncryptionBucketDefault Encryption = "bucket-default"
	// EncryptionS3 requests SSE-S3 (keys managed by the object store).
	EncryptionS3 Encryption = "sse-s3"
	// EncryptionKMS requests SSE-KMS with Config.KMSKeyID.
	EncryptionKMS Encryption = "sse-kms"
)

// Config says where artifact bytes live. It mirrors the object-store section
// of the traust configuration contract.
type Config struct {
	// Endpoint is host[:port]. Empty means AWS S3 (s3.amazonaws.com).
	Endpoint string
	// Region is the bucket's region; required for AWS S3.
	Region string
	// Bucket holds the artifacts.
	Bucket string
	// Prefix is prepended to every key, e.g. "prod/". May be empty.
	Prefix string
	// Insecure disables TLS. Only for local test endpoints.
	Insecure bool
	// Encryption and KMSKeyID select server-side encryption.
	Encryption Encryption
	KMSKeyID   string
	// MaxObjectBytes bounds how much GetArtifact reads. Zero means 64 MiB.
	MaxObjectBytes int64
	// Credentials overrides the default environment-then-IAM chain, for
	// callers that already hold a credentials provider.
	Credentials *credentials.Credentials
}

const defaultMaxObjectBytes = 64 << 20

// Store is a storage.ObjectStore backed by S3.
type Store struct {
	client *minio.Client
	cfg    Config
	sse    encrypt.ServerSide
}

var _ storage.ObjectStore = (*Store)(nil)

// New validates cfg and builds a Store. It does not contact the endpoint.
func New(cfg Config) (*Store, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("s3store: bucket is required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "s3.amazonaws.com"
		if cfg.Region == "" {
			return nil, errors.New("s3store: region is required for AWS S3")
		}
	}
	if cfg.MaxObjectBytes <= 0 {
		cfg.MaxObjectBytes = defaultMaxObjectBytes
	}
	var sse encrypt.ServerSide
	switch cfg.Encryption {
	case EncryptionBucketDefault, "":
	case EncryptionS3:
		sse = encrypt.NewSSE()
	case EncryptionKMS:
		if cfg.KMSKeyID == "" {
			return nil, errors.New("s3store: sse-kms needs a KMS key id")
		}
		kms, err := encrypt.NewSSEKMS(cfg.KMSKeyID, nil)
		if err != nil {
			return nil, fmt.Errorf("s3store: kms key: %w", err)
		}
		sse = kms
	default:
		return nil, fmt.Errorf("s3store: unknown encryption %q", cfg.Encryption)
	}
	creds := cfg.Credentials
	if creds == nil {
		creds = credentials.NewChainCredentials([]credentials.Provider{
			&credentials.EnvAWS{},
			&credentials.EnvMinio{},
			&credentials.IAM{Client: &http.Client{Transport: http.DefaultTransport}},
		})
	}
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  creds,
		Secure: !cfg.Insecure,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("s3store: client: %w", err)
	}
	return &Store{client: client, cfg: cfg, sse: sse}, nil
}

// Key returns the object key for a digest.
func (s *Store) Key(digest string) string { return storage.ObjectKey(s.cfg.Prefix, digest) }

// PutArtifact writes payload under its digest.
func (s *Store) PutArtifact(ctx context.Context, digest string, payload []byte) error {
	_, err := s.client.PutObject(
		ctx,
		s.cfg.Bucket,
		s.Key(digest),
		bytes.NewReader(payload),
		int64(len(payload)),
		minio.PutObjectOptions{ContentType: "application/json", ServerSideEncryption: s.sse},
	)
	if err != nil {
		return fmt.Errorf("s3store: put %s: %w", s.Key(digest), err)
	}
	return nil
}

// GetArtifact reads the bytes stored under digest.
func (s *Store) GetArtifact(ctx context.Context, digest string) ([]byte, error) {
	obj, err := s.client.GetObject(ctx, s.cfg.Bucket, s.Key(digest), minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("s3store: get %s: %w", s.Key(digest), err)
	}
	defer func() { _ = obj.Close() }()
	data, err := io.ReadAll(io.LimitReader(obj, s.cfg.MaxObjectBytes+1))
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, fmt.Errorf("s3store: %s: %w", s.Key(digest), storage.ErrNotFound)
		}
		return nil, fmt.Errorf("s3store: read %s: %w", s.Key(digest), err)
	}
	if int64(len(data)) > s.cfg.MaxObjectBytes {
		return nil, fmt.Errorf("s3store: %s exceeds %d bytes", s.Key(digest), s.cfg.MaxObjectBytes)
	}
	return data, nil
}
