package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	minio "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.uber.org/zap"
)

type S3 struct {
	Logger *zap.Logger

	// S3
	Client    *minio.Client
	Host      string `json:"host"`
	Bucket    string `json:"bucket"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	Prefix    string `json:"prefix"`

	// EncryptionKey is optional. If you do not wish to encrypt your certficates and key inside the S3 bucket, leave it empty.
	EncryptionKey string `json:"encryption_key"`

	iowrap IO
}

func init() {
	caddy.RegisterModule(new(S3))
}

func (s3 *S3) Provision(caddyCtx caddy.Context) error {
	s3.Logger = caddyCtx.Logger(s3)

	// S3 Client
	client, err := minio.New(s3.Host, &minio.Options{
		Creds:  credentials.NewStaticV4(s3.AccessKey, s3.SecretKey, ""),
		Secure: true,
	})

	if err != nil {
		return err
	}

	s3.Client = client
	
	// Check if bucket exists
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	exists, err := s3.Client.BucketExists(ctx, s3.Bucket)
	if err != nil {
		return fmt.Errorf("failed to check if bucket exists: %w", err)
	}
	if !exists {
		return fmt.Errorf("bucket %s does not exist", s3.Bucket)
	}

	if len(s3.EncryptionKey) == 0 {
		s3.Logger.Info("Clear text certificate storage active")
		s3.iowrap = &CleartextIO{}
	} else if len(s3.EncryptionKey) != 32 {
		s3.Logger.Error("encryption key must have exactly 32 bytes")
		return errors.New("encryption key must have exactly 32 bytes")
	} else {
		s3.Logger.Info("Encrypted certificate storage active")
		sb := &SecretBoxIO{}
		copy(sb.SecretKey[:], []byte(s3.EncryptionKey))
		s3.iowrap = sb
	}

	return nil
}

func (s3 *S3) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.storage.s3",
		New: func() caddy.Module {
			return new(S3)
		},
	}
}

var (
	LockExpiration   = 2 * time.Minute
	LockPollInterval = 1 * time.Second
	LockTimeout      = 15 * time.Second
)

func (s3 *S3) Lock(ctx context.Context, key string) error {
	s3.Logger.Info(fmt.Sprintf("Lock: attempting to lock %v", s3.objName(key)))
	var startedAt = time.Now()

	for {
		s3.Logger.Debug(fmt.Sprintf("Lock: checking if lock file exists for %v", s3.objName(key)))
		obj, err := s3.Client.GetObject(ctx, s3.Bucket, s3.objLockName(key), minio.GetObjectOptions{})
		if err != nil {
			s3.Logger.Debug(fmt.Sprintf("Lock: error getting lock file: %v", err))
			
			// Check if the error is because the object doesn't exist
			if strings.Contains(err.Error(), "key does not exist") || 
			   strings.Contains(err.Error(), "NoSuchKey") {
				// Object doesn't exist, try to create lock file
				s3.Logger.Info(fmt.Sprintf("Lock: lock file doesn't exist, attempting to create for %v", s3.objLockName(key)))
				return s3.putLockFile(ctx, key)
			}
			
			// For other errors, retry if within timeout
			if startedAt.Add(LockTimeout).Before(time.Now()) {
				s3.Logger.Error(fmt.Sprintf("Lock: failed to check lock file after timeout: %v", err))
				return fmt.Errorf("failed to check lock file: %w", err)
			}
			time.Sleep(LockPollInterval)
			continue
		}
		
		// Ensure object is closed to prevent goroutine leaks
		defer obj.Close()
		
		s3.Logger.Debug(fmt.Sprintf("Lock: reading lock file content for %v", s3.objName(key)))
		buf, err := io.ReadAll(obj)
		if err != nil {
			// Close explicitly in case defer doesn't execute in loop
			obj.Close()
			
			s3.Logger.Debug(fmt.Sprintf("Lock: error reading lock file: %v", err))
			// Retry if within timeout
			if startedAt.Add(LockTimeout).Before(time.Now()) {
				s3.Logger.Error(fmt.Sprintf("Lock: failed to read lock file after timeout: %v", err))
				return fmt.Errorf("failed to read lock file: %w", err)
			}
			time.Sleep(LockPollInterval)
			continue
		}
		
		s3.Logger.Debug(fmt.Sprintf("Lock: parsing lock timestamp for %v: %s", s3.objName(key), string(buf)))
		lt, err := time.Parse(time.RFC3339, string(buf))
		if err != nil {
			// Lock file does not make sense, overwrite.
			s3.Logger.Info(fmt.Sprintf("Lock: invalid timestamp in lock file, overwriting for %v", s3.objName(key)))
			obj.Close()
			return s3.putLockFile(ctx, key)
		}
		
		if lt.Add(LockTimeout).Before(time.Now()) {
			// Existing lock file expired, overwrite.
			s3.Logger.Info(fmt.Sprintf("Lock: lock file expired, overwriting for %v", s3.objName(key)))
			obj.Close()
			return s3.putLockFile(ctx, key)
		}

		// Lock is still valid, wait
		s3.Logger.Debug(fmt.Sprintf("Lock: lock is still valid for %v, waiting", s3.objName(key)))
		obj.Close()
		
		if startedAt.Add(LockTimeout).Before(time.Now()) {
			s3.Logger.Error(fmt.Sprintf("Lock: timeout waiting for lock for %v", s3.objName(key)))
			return errors.New("acquiring lock failed")
		}
		time.Sleep(LockPollInterval)
	}
}

func (s3 *S3) putLockFile(ctx context.Context, key string) error {
	// Object does not exist, we're creating a lock file.
	s3.Logger.Debug(fmt.Sprintf("putLockFile: creating lock file for %v", s3.objLockName(key)))
	r := bytes.NewReader([]byte(time.Now().Format(time.RFC3339)))
	
	// Use a context with timeout to prevent hanging operations
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	
	s3.Logger.Debug(fmt.Sprintf("putLockFile: putting object to bucket %s with key %s", s3.Bucket, s3.objLockName(key)))
	_, err := s3.Client.PutObject(ctx, s3.Bucket, s3.objLockName(key), r, int64(r.Len()), minio.PutObjectOptions{})
	if err != nil {
		s3.Logger.Error(fmt.Sprintf("putLockFile: failed to put lock file: %v", err))
	} else {
		s3.Logger.Debug(fmt.Sprintf("putLockFile: successfully created lock file for %v", s3.objLockName(key)))
	}
	return err
}

func (s3 *S3) Unlock(ctx context.Context, key string) error {
	s3.Logger.Info(fmt.Sprintf("Release lock: %v", s3.objName(key)))
	// Use a context with timeout to prevent hanging operations
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s3.Client.RemoveObject(ctx, s3.Bucket, s3.objLockName(key), minio.RemoveObjectOptions{})
}

func (s3 *S3) Store(ctx context.Context, key string, value []byte) error {
	r := s3.iowrap.ByteReader(value)
	s3.Logger.Info(fmt.Sprintf("Store: %v, %v bytes", s3.objName(key), len(value)))
	// Use a context with timeout to prevent hanging operations
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err := s3.Client.PutObject(ctx,
		s3.Bucket,
		s3.objName(key),
		r,
		int64(r.Len()),
		minio.PutObjectOptions{},
	)
	return err
}

func (s3 *S3) Load(ctx context.Context, key string) ([]byte, error) {
	s3.Logger.Info(fmt.Sprintf("Load: %v", s3.objName(key)))
	r, err := s3.Client.GetObject(ctx, s3.Bucket, s3.objName(key), minio.GetObjectOptions{})
	if err != nil {
		if err.Error() == "The specified key does not exist." {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}
	
	// Always ensure the object is closed to prevent goroutine leaks
	defer r.Close()
	
	if r != nil {
		// AWS (at least) doesn't return an error on key doesn't exist. We have
		// to examine the empty object returned.
		_, err = r.Stat()
		if err != nil {
			er := minio.ToErrorResponse(err)
			if er.StatusCode == 404 {
				return nil, fs.ErrNotExist
			}
			return nil, err
		}
	}
	
	// Create a wrapped reader that properly handles the object stream
	wrappedReader := s3.iowrap.WrapReader(r)
	buf, err := io.ReadAll(wrappedReader)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (s3 *S3) Delete(ctx context.Context, key string) error {
	s3.Logger.Info(fmt.Sprintf("Delete: %v", s3.objName(key)))
	// Use a context with timeout to prevent hanging operations
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s3.Client.RemoveObject(ctx, s3.Bucket, s3.objName(key), minio.RemoveObjectOptions{})
}

func (s3 *S3) Exists(ctx context.Context, key string) bool {
	s3.Logger.Info(fmt.Sprintf("Exists: %v", s3.objName(key)))
	// Use a context with timeout to prevent hanging operations
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err := s3.Client.StatObject(ctx, s3.Bucket, s3.objName(key), minio.StatObjectOptions{})
	return err == nil
}

func (s3 *S3) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	var keys []string
	// Use a context with timeout to prevent hanging operations
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second) // Longer timeout for listing
	defer cancel()
	
	// Construct the full prefix by combining the storage prefix and the requested prefix
	fullPrefix := s3.objName(prefix)
	s3.Logger.Info(fmt.Sprintf("List: prefix=%s, recursive=%v", fullPrefix, recursive))
	
	for obj := range s3.Client.ListObjects(ctx, s3.Bucket, minio.ListObjectsOptions{
		Prefix:    fullPrefix,
		Recursive: recursive,
	}) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		
		// Extract the key by removing the storage prefix
		// This ensures we return keys in the format expected by certmagic
		storagePrefix := s3.objName("")
		key := strings.TrimPrefix(obj.Key, storagePrefix)
		
		// Skip lock files
		if strings.HasSuffix(key, ".lock") {
			continue
		}
		
		// Remove leading slash if present
		key = strings.TrimPrefix(key, "/")
		
		keys = append(keys, key)
	}
	return keys, nil
}

func (s3 *S3) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	s3.Logger.Info(fmt.Sprintf("Stat: %v", s3.objName(key)))
	var ki certmagic.KeyInfo
	
	// Use a context with timeout to prevent hanging operations
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	
	oi, err := s3.Client.StatObject(ctx, s3.Bucket, s3.objName(key), minio.StatObjectOptions{})
	if err != nil {
		return ki, fs.ErrNotExist
	}
	ki.Key = key
	ki.Size = oi.Size
	ki.Modified = oi.LastModified
	ki.IsTerminal = true
	return ki, nil
}

func (s3 *S3) objName(key string) string {
	return fmt.Sprintf("%s/%s", strings.TrimPrefix(s3.Prefix, "/"), strings.TrimPrefix(key, "/"))
}

func (s3 *S3) objLockName(key string) string {
	return s3.objName(key) + ".lock"
}

// CertMagicStorage converts s to a certmagic.Storage instance.
func (s3 *S3) CertMagicStorage() (certmagic.Storage, error) {
	return s3, nil
}

func (s3 *S3) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		key := d.Val()
		var value string

		if !d.Args(&value) {
			continue
		}

		switch key {
		case "host":
			s3.Host = value
		case "bucket":
			s3.Bucket = value
		case "access_key":
			s3.AccessKey = value
		case "secret_key":
			s3.SecretKey = value
		case "prefix":
			if value != "" {
				s3.Prefix = value
			} else {
				s3.Prefix = "acme"
			}
		case "encryption_key":
			s3.EncryptionKey = value
		}
	}
	return nil
}

var (
	_ caddy.Provisioner      = (*S3)(nil)
	_ caddy.StorageConverter = (*S3)(nil)
	_ caddyfile.Unmarshaler  = (*S3)(nil)
)
