package s3

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	s3sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"go.uber.org/zap"
)

var (
	// LockExpiration is how long a lock may go without being refreshed
	// before other instances treat its holder as gone and take it over.
	LockExpiration = 2 * time.Minute
	// LockRefreshInterval is how often a held lock is rewritten to show
	// its holder is still alive. It must be well below LockExpiration.
	LockRefreshInterval = 5 * time.Second
	// LockPollInterval is how often a waiting instance checks the lock.
	LockPollInterval = 1 * time.Second
	// LockTimeout bounds how long Lock keeps retrying storage errors. It
	// does not bound waiting for a live lock: Lock waits for that until the
	// lock is released, goes stale, or ctx is done.
	LockTimeout = 15 * time.Second
)

// A lock is an object at objLockName(key). It is created with
// If-None-Match: *, so exactly one instance can create it, and every later
// write to it or removal of it names the ETag its writer last saw, so an
// instance only ever replaces the lock it holds or the stale one it read.
// The object's body is the time of the last write, readable by older
// versions of this module; staleness is judged by the object's LastModified
// against the Date of the response, both set by the storage service, so
// holders and waiters need not agree on the time.

type heldLock struct {
	mu   sync.Mutex
	etag string
	stop chan struct{}
	done chan struct{}
}

func (h *heldLock) currentETag() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.etag
}

func (h *heldLock) setETag(etag string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.etag = etag
}

// Lock acquires the lock for key. It blocks until the lock is free or
// stale, or ctx is done, and gives up if storage keeps failing for longer
// than LockTimeout.
func (s3 *S3) Lock(ctx context.Context, key string) error {
	name := s3.objLockName(key)
	s3.Logger.Info("acquiring lock", zap.String("key", name))

	var failingSince time.Time
	for {
		attemptedAt := time.Now()
		etag, err := s3.tryLock(ctx, name)
		if err == nil && etag != "" {
			s3.hold(name, etag)
			return nil
		}
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return fmt.Errorf("acquiring lock: %w", ctxErr)
			}
			if failingSince.IsZero() {
				failingSince = attemptedAt
			}
			if time.Since(failingSince) > LockTimeout {
				return fmt.Errorf("acquiring lock failed: %w", err)
			}
		} else {
			failingSince = time.Time{}
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("acquiring lock: %w", ctx.Err())
		case <-time.After(LockPollInterval):
		}
	}
}

// tryLock makes one attempt at the lock. It returns the lock object's ETag
// when the lock is now held, "" and no error when another instance holds a
// live lock, and an error when storage failed.
func (s3 *S3) tryLock(ctx context.Context, name string) (string, error) {
	etag, err := s3.putLock(ctx, name, func(in *s3sdk.PutObjectInput) {
		in.IfNoneMatch = aws.String("*")
	})
	if err == nil {
		return etag, nil
	}
	if !isPreconditionFailed(err) {
		return "", err
	}

	head, err := s3.Client.HeadObject(ctx, &s3sdk.HeadObjectInput{
		Bucket: aws.String(s3.Bucket),
		Key:    aws.String(name),
	})
	if err != nil {
		if isNotFound(err) {
			// Released since we tried; the next attempt may take it.
			return "", nil
		}
		return "", err
	}
	now, ok := awsmiddleware.GetServerTime(head.ResultMetadata)
	if !ok {
		now = time.Now()
	}
	if head.LastModified == nil || now.Sub(*head.LastModified) < LockExpiration {
		return "", nil
	}

	// The holder stopped refreshing it. Replace it, but only if it is still
	// the object we just read: when several instances find the same stale
	// lock, one replacement succeeds and the rest fail the precondition.
	etag, err = s3.putLock(ctx, name, func(in *s3sdk.PutObjectInput) {
		in.IfMatch = head.ETag
	})
	if err != nil {
		if isPreconditionFailed(err) || isNotFound(err) {
			return "", nil
		}
		return "", err
	}
	s3.Logger.Warn("replaced stale lock",
		zap.String("key", name),
		zap.Time("last_refreshed", *head.LastModified),
	)
	return etag, nil
}

func (s3 *S3) putLock(ctx context.Context, name string, condition func(*s3sdk.PutObjectInput)) (string, error) {
	// Nanoseconds, so that no two writes share a body: services compute the
	// ETag from the content, and the ETag is how a holder tells its own lock
	// from one that replaced it. RFC 3339 parsing still accepts the fraction.
	body := time.Now().UTC().Format(time.RFC3339Nano)
	input := &s3sdk.PutObjectInput{
		Bucket:        aws.String(s3.Bucket),
		Key:           aws.String(name),
		Body:          strings.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
	}
	condition(input)

	out, err := s3.Client.PutObject(ctx, input)
	if err != nil {
		return "", err
	}
	etag := aws.ToString(out.ETag)
	if etag == "" {
		return "", errors.New("storage returned no ETag for the lock object")
	}
	return etag, nil
}

// hold records a newly acquired lock and keeps it fresh until Unlock.
func (s3 *S3) hold(name, etag string) {
	h := &heldLock{etag: etag, stop: make(chan struct{}), done: make(chan struct{})}

	s3.locksMu.Lock()
	if s3.locks == nil {
		s3.locks = make(map[string]*heldLock)
	}
	s3.locks[name] = h
	s3.locksMu.Unlock()

	go s3.keepFresh(name, h)
}

func (s3 *S3) keepFresh(name string, h *heldLock) {
	defer close(h.done)

	ticker := time.NewTicker(LockRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.stop:
			return
		case <-ticker.C:
		}

		ctx, cancel := context.WithTimeout(context.Background(), LockRefreshInterval)
		etag, err := s3.putLock(ctx, name, func(in *s3sdk.PutObjectInput) {
			in.IfMatch = aws.String(h.currentETag())
		})
		cancel()

		switch {
		case err == nil:
			h.setETag(etag)
		case isPreconditionFailed(err) || isNotFound(err):
			// Another instance judged the lock stale and took it.
			s3.Logger.Error("lock lost to another instance while held", zap.String("key", name))
			return
		default:
			s3.Logger.Warn("refreshing lock failed", zap.String("key", name), zap.Error(err))
		}
	}
}

// Unlock releases the lock for key if this instance still holds it. A lock
// another instance has since taken over is left in place.
func (s3 *S3) Unlock(ctx context.Context, key string) error {
	name := s3.objLockName(key)
	s3.Logger.Info("releasing lock", zap.String("key", name))

	s3.locksMu.Lock()
	h := s3.locks[name]
	delete(s3.locks, name)
	s3.locksMu.Unlock()
	if h == nil {
		return fmt.Errorf("releasing lock %s: not held by this instance", name)
	}

	close(h.stop)
	<-h.done

	// Refresh the lock before deleting it, so that no waiter can judge it
	// stale while the delete is in flight on services that ignore If-Match
	// on DELETE.
	ctx, cancel := context.WithTimeout(ctx, LockExpiration/2)
	defer cancel()
	etag, err := s3.putLock(ctx, name, func(in *s3sdk.PutObjectInput) {
		in.IfMatch = aws.String(h.currentETag())
	})
	switch {
	case err == nil:
	case isNotFound(err):
		return nil
	case isPreconditionFailed(err):
		s3.Logger.Warn("lock was taken over by another instance; leaving it", zap.String("key", name))
		return nil
	default:
		return fmt.Errorf("releasing lock %s: %w", name, err)
	}

	_, err = s3.Client.DeleteObject(ctx, &s3sdk.DeleteObjectInput{
		Bucket:  aws.String(s3.Bucket),
		Key:     aws.String(name),
		IfMatch: aws.String(etag),
	})
	if err != nil && !isPreconditionFailed(err) && !isNotFound(err) {
		return fmt.Errorf("releasing lock %s: %w", name, err)
	}
	return nil
}

// isPreconditionFailed reports whether a conditional request was refused
// because the object's state did not match: 412, or 409 when the service
// saw a competing conditional write in flight.
func isPreconditionFailed(err error) bool {
	var re *awshttp.ResponseError
	if !errors.As(err, &re) {
		return false
	}
	switch re.HTTPStatusCode() {
	case http.StatusPreconditionFailed, http.StatusConflict:
		return true
	}
	return false
}

func isNotFound(err error) bool {
	var nsk *types.NoSuchKey
	var nf *types.NotFound
	if errors.As(err, &nsk) || errors.As(err, &nf) {
		return true
	}
	var re *awshttp.ResponseError
	return errors.As(err, &re) && re.HTTPStatusCode() == http.StatusNotFound
}
