package cmgs3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/caddyserver/certmagic"
	minio "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type GenS3Storage struct {
	basePath string
	bucket   string
	s3client *minio.Client

	iowrap IO
}

func NewGenericS3Storage(endpoint, bucket, accessKeyID, secretAccessKey, basePath string, encryptionKey []byte) (*GenS3Storage, error) {
	gs3 := &GenS3Storage{
		basePath: basePath,
		bucket:   bucket,
	}

	if encryptionKey == nil || len(encryptionKey) == 0 {
		log.Println("Clear text certificate storage active")
		gs3.iowrap = &CleartextIO{}
	} else if len(encryptionKey) != 32 {
		return nil, errors.New("encryption key must have exactly 32 bytes")
	} else {
		log.Println("Encrypted certificate storage active")
		sb := &SecretBoxIO{}
		copy(sb.SecretKey[:], encryptionKey)
		gs3.iowrap = sb
	}

	var err error
	gs3.s3client, err = minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
		Secure: true,
	})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok, err := gs3.s3client.BucketExists(ctx, bucket)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("S3 bucket %s does not exist", bucket)
	}
	return gs3, nil
}

var (
	LockExpiration   = 2 * time.Minute
	LockPollInterval = 1 * time.Second
	LockTimeout      = 15 * time.Second
)

func (gs *GenS3Storage) Lock(ctx context.Context, key string) error {
	var startedAt = time.Now()

	for {
		obj, err := gs.s3client.GetObject(ctx, gs.bucket, gs.objLockName(key), minio.GetObjectOptions{})
		if err == nil {
			return gs.putLockFile(key)
		}
		buf, err := ioutil.ReadAll(obj)
		if err != nil {
			// Retry
			continue
		}
		lt, err := time.Parse(time.RFC3339, string(buf))
		if err != nil {
			// Lock file does not make sense, overwrite.
			return gs.putLockFile(key)
		}
		if lt.Add(LockTimeout).Before(time.Now()) {
			// Existing lock file expired, overwrite.
			return gs.putLockFile(key)
		}

		if startedAt.Add(LockTimeout).Before(time.Now()) {
			return errors.New("acquiring lock failed")
		}
		time.Sleep(LockPollInterval)
	}
	return errors.New("locking failed")
}

func (gs *GenS3Storage) putLockFile(key string) error {
	// Object does not exist, we're creating a lock file.
	r := bytes.NewReader([]byte(time.Now().Format(time.RFC3339)))
	_, err := gs.s3client.PutObject(context.Background(), gs.bucket, gs.objLockName(key), r, int64(r.Len()), minio.PutObjectOptions{})
	return err
}

func (gs *GenS3Storage) Unlock(key string) error {
	return gs.s3client.RemoveObject(context.Background(), gs.bucket, gs.objLockName(key), minio.RemoveObjectOptions{})
}

func (gs *GenS3Storage) Store(key string, value []byte) error {
	log.Printf("storing %v", key)
	r := gs.iowrap.NewReader(value)
	_, err := gs.s3client.PutObject(context.Background(), gs.bucket, gs.objName(key), r, int64(r.Len()), minio.PutObjectOptions{})
	return err
}

func (gs *GenS3Storage) Load(key string) ([]byte, error) {
	r, err := gs.s3client.GetObject(context.Background(), gs.bucket, gs.objName(key), minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	oi, err := r.Stat()
	if err != nil {
		return nil, err
	}
	if oi.Size == 0 {
		return nil, certmagic.ErrNotExist(err)
	}
	defer r.Close()
	log.Printf("loading %v", key)
	buf, err := ioutil.ReadAll(gs.iowrap.Read(r))
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (gs *GenS3Storage) Delete(key string) error {
	return gs.s3client.RemoveObject(context.Background(), gs.bucket, gs.objName(key), minio.RemoveObjectOptions{})
}

func (gs *GenS3Storage) Exists(key string) bool {
	log.Printf("exists %v", key)
	_, err := gs.s3client.StatObject(context.Background(), gs.bucket, gs.objName(key), minio.StatObjectOptions{})
	return err == nil
}

func (gs *GenS3Storage) List(prefix string, recursive bool) ([]string, error) {
	var keys []string
	for obj := range gs.s3client.ListObjects(context.Background(), gs.bucket, minio.ListObjectsOptions{
		Prefix:    gs.objName(""),
		Recursive: true,
	}) {
		keys = append(keys, obj.Key)
	}
	return keys, nil
}

func (gs *GenS3Storage) Stat(key string) (certmagic.KeyInfo, error) {
	log.Printf("stat %v", key)
	var ki certmagic.KeyInfo
	oi, err := gs.s3client.StatObject(context.Background(), gs.bucket, gs.objName(key), minio.StatObjectOptions{})
	if err != nil {
		return ki, certmagic.ErrNotExist(err)
	}
	ki.Key = key
	ki.Size = oi.Size
	ki.Modified = oi.LastModified
	ki.IsTerminal = true
	return ki, nil
}

func (gs *GenS3Storage) objName(key string) string {
	return gs.basePath + "_" + key
}

func (gs *GenS3Storage) objLockName(key string) string {
	return gs.objName(key) + ".lock"
}
