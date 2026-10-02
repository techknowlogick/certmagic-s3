package s3

import (
	"context"
	"errors"
	"fmt"
	"sync"
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

// setLockTimings shortens the lock timings for one test.
func setLockTimings(t *testing.T, expiration, refresh, poll, timeout time.Duration) {
	t.Helper()
	origExp, origRefresh, origPoll, origTimeout := LockExpiration, LockRefreshInterval, LockPollInterval, LockTimeout
	LockExpiration, LockRefreshInterval, LockPollInterval, LockTimeout = expiration, refresh, poll, timeout
	t.Cleanup(func() {
		LockExpiration, LockRefreshInterval, LockPollInterval, LockTimeout = origExp, origRefresh, origPoll, origTimeout
	})
}

// The fake must refuse a second create, or the tests below prove nothing.
func TestFakeS3RefusesASecondCreate(t *testing.T) {
	f, srv := newFakeS3(t)
	s := f.instance(srv)

	if _, err := s.putLock(context.Background(), "k", func(in *s3sdk.PutObjectInput) { in.IfNoneMatch = aws.String("*") }); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := s.putLock(context.Background(), "k", func(in *s3sdk.PutObjectInput) { in.IfNoneMatch = aws.String("*") })
	if !isPreconditionFailed(err) {
		t.Fatalf("second create: want a precondition failure, got %v", err)
	}
}

// runContenders has each instance take the lock rounds times and reports
// the most instances that ever held it at once.
func runContenders(t *testing.T, instances []*S3, rounds int, hold time.Duration) int32 {
	t.Helper()
	var active, most int32
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, s := range instances {
		wg.Add(1)
		go func(s *S3) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if err := s.Lock(context.Background(), "issue_cert_example.com"); err != nil {
					t.Errorf("Lock: %v", err)
					return
				}
				mu.Lock()
				active++
				if active > most {
					most = active
				}
				mu.Unlock()

				time.Sleep(hold)

				mu.Lock()
				active--
				mu.Unlock()
				if err := s.Unlock(context.Background(), "issue_cert_example.com"); err != nil {
					t.Errorf("Unlock: %v", err)
					return
				}
			}
		}(s)
	}
	wg.Wait()
	return most
}

func TestLockIsExclusiveAcrossInstances(t *testing.T) {
	setLockTimings(t, 2*time.Minute, time.Second, 2*time.Millisecond, 5*time.Second)
	f, srv := newFakeS3(t)

	var instances []*S3
	for i := 0; i < 8; i++ {
		instances = append(instances, f.instance(srv))
	}
	if most := runContenders(t, instances, 5, 5*time.Millisecond); most != 1 {
		t.Fatalf("%d instances held the lock at once", most)
	}
	if _, ok := f.get("issue_cert_example.com.lock"); ok {
		t.Fatal("lock object left behind after every holder released it")
	}
}

// When several instances find the same stale lock, exactly one replaces it.
func TestStaleLockIsTakenOverByOneInstance(t *testing.T) {
	setLockTimings(t, time.Minute, time.Second, 2*time.Millisecond, 5*time.Second)
	f, srv := newFakeS3(t)
	f.seed("issue_cert_example.com.lock", time.Now().Add(-time.Hour))

	var instances []*S3
	for i := 0; i < 8; i++ {
		instances = append(instances, f.instance(srv))
	}
	if most := runContenders(t, instances, 1, 20*time.Millisecond); most != 1 {
		t.Fatalf("%d instances held the lock at once", most)
	}
}

// A holder that outlasts both LockTimeout and LockExpiration keeps the lock,
// because it refreshes it; a waiter gets it only once it is released.
func TestLongHeldLockIsNotTakenOver(t *testing.T) {
	setLockTimings(t, 2*time.Second, 200*time.Millisecond, 20*time.Millisecond, 50*time.Millisecond)
	f, srv := newFakeS3(t)
	holder, waiter := f.instance(srv), f.instance(srv)

	if err := holder.Lock(context.Background(), "k"); err != nil {
		t.Fatalf("holder Lock: %v", err)
	}

	acquired := make(chan time.Time, 1)
	go func() {
		if err := waiter.Lock(context.Background(), "k"); err != nil {
			t.Errorf("waiter Lock: %v", err)
			return
		}
		acquired <- time.Now()
	}()

	time.Sleep(3 * time.Second)
	select {
	case <-acquired:
		t.Fatal("waiter took a lock its holder was still refreshing")
	default:
	}

	released := time.Now()
	if err := holder.Unlock(context.Background(), "k"); err != nil {
		t.Fatalf("holder Unlock: %v", err)
	}
	select {
	case at := <-acquired:
		if at.Before(released) {
			t.Fatal("waiter acquired before the holder released")
		}
		if err := waiter.Unlock(context.Background(), "k"); err != nil {
			t.Fatalf("waiter Unlock: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not acquire after the release")
	}
}

// A holder whose lock was taken over must not delete the new holder's lock,
// even when the two were written in the same second.
func TestUnlockLeavesALockTakenOverByAnother(t *testing.T) {
	for _, ignoreIfMatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("service ignores conditional delete=%v", ignoreIfMatch), func(t *testing.T) {
			f, srv := newFakeS3(t)
			f.ignoreDeleteIfMatch = ignoreIfMatch
			s := f.instance(srv)

			if err := s.Lock(context.Background(), "k"); err != nil {
				t.Fatalf("Lock: %v", err)
			}
			// Another instance replaces it at once, through the same write path,
			// so the two bodies are written within the same second.
			newOwner, err := f.instance(srv).putLock(context.Background(), "k.lock", func(*s3sdk.PutObjectInput) {})
			if err != nil {
				t.Fatalf("replacing the lock: %v", err)
			}

			if err := s.Unlock(context.Background(), "k"); err != nil {
				t.Fatalf("Unlock: %v", err)
			}
			obj, ok := f.get("k.lock")
			if !ok || obj.etag != newOwner {
				t.Fatal("Unlock removed a lock another instance held")
			}
		})
	}
}

func TestUnlockReleasesItsOwnLock(t *testing.T) {
	for _, ignoreIfMatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("service ignores conditional delete=%v", ignoreIfMatch), func(t *testing.T) {
			f, srv := newFakeS3(t)
			f.ignoreDeleteIfMatch = ignoreIfMatch
			s := f.instance(srv)

			if err := s.Lock(context.Background(), "k"); err != nil {
				t.Fatalf("Lock: %v", err)
			}
			if err := s.Unlock(context.Background(), "k"); err != nil {
				t.Fatalf("Unlock: %v", err)
			}
			if _, ok := f.get("k.lock"); ok {
				t.Fatal("lock object still present after Unlock")
			}
		})
	}
}

func TestUnlockWithoutLockIsAnError(t *testing.T) {
	f, srv := newFakeS3(t)
	f.seed("k.lock", time.Now())

	if err := f.instance(srv).Unlock(context.Background(), "k"); err == nil {
		t.Fatal("want an error releasing a lock this instance never took")
	}
	if _, ok := f.get("k.lock"); !ok {
		t.Fatal("Unlock without Lock removed another instance's lock")
	}
}

// Older versions of this module read the lock body as an RFC 3339 time and
// treat it as stale after LockTimeout, so the body must stay in that form
// and keep being refreshed for them to wait during a mixed rollout.
func TestLockBodyStaysReadableByOlderVersions(t *testing.T) {
	setLockTimings(t, time.Minute, 50*time.Millisecond, 10*time.Millisecond, time.Second)
	f, srv := newFakeS3(t)
	s := f.instance(srv)

	if err := s.Lock(context.Background(), "k"); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	defer func() { _ = s.Unlock(context.Background(), "k") }()

	first, _ := f.get("k.lock")
	time.Sleep(200 * time.Millisecond)
	later, _ := f.get("k.lock")

	if _, err := time.Parse(time.RFC3339, string(later.body)); err != nil {
		t.Fatalf("lock body %q is not an RFC 3339 time: %v", later.body, err)
	}
	if later.etag == first.etag {
		t.Fatal("held lock was not refreshed")
	}
}
