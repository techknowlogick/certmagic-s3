package s3

import (
	"crypto/md5" // #nosec G501 -- S3 computes ETags this way; nothing here is security
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	s3sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"go.uber.org/zap"
)

// fakeS3 is an in-memory, path-style S3 endpoint holding single objects. It
// applies each request atomically and honours If-None-Match: * and If-Match
// on PUT the way S3 and S3-compatible services with conditional writes do.
type fakeS3 struct {
	t *testing.T

	mu      sync.Mutex
	objects map[string]*fakeObject

	// ignoreDeleteIfMatch deletes regardless of If-Match, as services that
	// do not support conditional deletes do.
	ignoreDeleteIfMatch bool
}

type fakeObject struct {
	body     []byte
	etag     string
	modified time.Time
}

func newFakeS3(t *testing.T) (*fakeS3, *httptest.Server) {
	t.Helper()
	f := &fakeS3{t: t, objects: make(map[string]*fakeObject)}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

// instance returns a new S3 storage talking to the fake, as a separate
// process would.
func (f *fakeS3) instance(srv *httptest.Server) *S3 {
	client := s3sdk.New(s3sdk.Options{
		BaseEndpoint:               aws.String(srv.URL),
		Region:                     "us-east-1",
		UsePathStyle:               true,
		Credentials:                credentials.NewStaticCredentialsProvider("id", "secret", ""),
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
	return &S3{Logger: zap.NewNop(), Client: client, Bucket: "test"}
}

// seed stores an object last written at modified.
func (f *fakeS3) seed(key string, modified time.Time) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.write(key, []byte(modified.UTC().Format(time.RFC3339)), modified)
}

func (f *fakeS3) get(key string) (fakeObject, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[key]
	if !ok {
		return fakeObject{}, false
	}
	return *obj, true
}

// write stores an object. Its ETag is the MD5 of its content, as S3 and
// S3-compatible services compute it for single-part uploads.
func (f *fakeS3) write(key string, body []byte, modified time.Time) string {
	etag := fmt.Sprintf("%q", fmt.Sprintf("%x", md5.Sum(body))) // #nosec G401 -- as above
	f.objects[key] = &fakeObject{body: body, etag: etag, modified: modified}
	return etag
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/test/")

	f.mu.Lock()
	defer f.mu.Unlock()
	obj, exists := f.objects[key]

	switch r.Method {
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			f.t.Errorf("fake s3: reading body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Header.Get("If-None-Match") == "*" && exists {
			writeError(w, http.StatusPreconditionFailed, "PreconditionFailed")
			return
		}
		if m := r.Header.Get("If-Match"); m != "" && (!exists || obj.etag != m) {
			if !exists {
				writeError(w, http.StatusNotFound, "NoSuchKey")
				return
			}
			writeError(w, http.StatusPreconditionFailed, "PreconditionFailed")
			return
		}
		w.Header().Set("ETag", f.write(key, body, time.Now()))
		w.WriteHeader(http.StatusOK)

	case http.MethodGet, http.MethodHead:
		if !exists {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeError(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("ETag", obj.etag)
		w.Header().Set("Last-Modified", obj.modified.UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Length", fmt.Sprint(len(obj.body)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(obj.body)
		}

	case http.MethodDelete:
		if m := r.Header.Get("If-Match"); m != "" && !f.ignoreDeleteIfMatch && exists && obj.etag != m {
			writeError(w, http.StatusPreconditionFailed, "PreconditionFailed")
			return
		}
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
}
