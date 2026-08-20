package s3

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	s3sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"go.uber.org/zap"
)

// newUnreachableS3 returns an S3 whose client fails every call with a
// non-NoSuchKey error (connection refused), exercising Lock's retry path.
func newUnreachableS3() *S3 {
	client := s3sdk.New(s3sdk.Options{
		BaseEndpoint: aws.String("http://127.0.0.1:1"),
		Region:       "us-east-1",
	})
	return &S3{Logger: zap.NewNop(), Client: client, Bucket: "test"}
}

// An already-expired context makes GetObject fail instantly with a
// non-NoSuchKey error. Lock must return the ctx error instead of
// retrying in a tight loop forever.
func TestLockReturnsOnExpiredContext(t *testing.T) {
	s := newUnreachableS3()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- s.Lock(ctx, "testlock") }()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled in error chain, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Lock still running after 5s: retry loop does not honor ctx")
	}
}

// A persistent GetObject error with a live context must give up after
// LockTimeout instead of retrying forever.
func TestLockGivesUpOnPersistentError(t *testing.T) {
	origTimeout, origPoll := LockTimeout, LockPollInterval
	LockTimeout, LockPollInterval = 300*time.Millisecond, 10*time.Millisecond
	defer func() { LockTimeout, LockPollInterval = origTimeout, origPoll }()

	s := newUnreachableS3()

	done := make(chan error, 1)
	go func() { done <- s.Lock(context.Background(), "testlock") }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("want error, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Lock still running after 5s: retry loop does not honor LockTimeout")
	}
}
