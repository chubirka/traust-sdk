package s3store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/traust-security/traust-sdk/go/v1/storage"
)

// TestRoundTripAgainstARealEndpoint runs only when S3STORE_TEST_ENDPOINT is
// set, e.g. against a disposable MinIO:
//
//	S3STORE_TEST_ENDPOINT=127.0.0.1:9000 S3STORE_TEST_ACCESS_KEY=... \
//	S3STORE_TEST_SECRET_KEY=... go test ./v1/storage/s3store/ -run RoundTrip
func TestRoundTripAgainstARealEndpoint(t *testing.T) {
	endpoint := os.Getenv("S3STORE_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("S3STORE_TEST_ENDPOINT not set")
	}
	ctx := context.Background()
	creds := credentials.NewStaticV4(
		os.Getenv("S3STORE_TEST_ACCESS_KEY"), os.Getenv("S3STORE_TEST_SECRET_KEY"), "",
	)
	bucket := "traust-s3store-test"
	admin, err := minio.New(endpoint, &minio.Options{Creds: creds, Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	if exists, _ := admin.BucketExists(ctx, bucket); !exists {
		if err := admin.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	store, err := New(Config{
		Endpoint: endpoint, Bucket: bucket, Prefix: "test/", Insecure: true, Credentials: creds,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"hello":"world"}`)
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	if err := store.PutArtifact(ctx, digest, payload); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetArtifact(ctx, digest)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("GetArtifact = %q, %v", got, err)
	}
	if _, err := admin.StatObject(ctx, bucket, "test/sha256/"+digest, minio.StatObjectOptions{}); err != nil {
		t.Fatalf("object not at the contract key: %v", err)
	}
	missing := "f" + digest[1:]
	if _, err := store.GetArtifact(ctx, missing); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing object = %v, want storage.ErrNotFound", err)
	}
	small, err := New(Config{
		Endpoint: endpoint, Bucket: bucket, Prefix: "test/", Insecure: true, Credentials: creds, MaxObjectBytes: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := small.GetArtifact(ctx, digest); err == nil {
		t.Fatal("oversized object was read")
	}
}
