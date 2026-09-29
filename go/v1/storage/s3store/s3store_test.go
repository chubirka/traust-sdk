package s3store

import (
	"strings"
	"testing"
)

const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestNewValidatesConfig(t *testing.T) {
	cases := map[string]struct {
		cfg  Config
		want string
	}{
		"bucket required":            {Config{Region: "us-east-1"}, "bucket is required"},
		"aws needs a region":         {Config{Bucket: "b"}, "region is required"},
		"kms needs a key":            {Config{Bucket: "b", Region: "us-east-1", Encryption: EncryptionKMS}, "needs a KMS key id"},
		"unknown encryption":         {Config{Bucket: "b", Region: "us-east-1", Encryption: "rot13"}, "unknown encryption"},
		"custom endpoint, no region": {Config{Bucket: "b", Endpoint: "minio.local:9000"}, ""},
		"sse-s3":                     {Config{Bucket: "b", Region: "us-east-1", Encryption: EncryptionS3}, ""},
		"bucket-default":             {Config{Bucket: "b", Region: "us-east-1", Encryption: EncryptionBucketDefault}, ""},
		"sse-kms":                    {Config{Bucket: "b", Region: "us-east-1", Encryption: EncryptionKMS, KMSKeyID: "arn:aws:kms:us-east-1:111122223333:key/abc"}, ""},
	}
	for name, tc := range cases {
		_, err := New(tc.cfg)
		if tc.want == "" && err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
		if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: error %v, want %q", name, err, tc.want)
		}
	}
}

func TestKeyUsesPrefixAndDigest(t *testing.T) {
	store, err := New(Config{Bucket: "b", Region: "us-east-1", Prefix: "prod/"})
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Key(digest); got != "prod/sha256/"+digest {
		t.Fatalf("Key = %q", got)
	}
}
