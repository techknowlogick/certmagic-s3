package s3

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	NonceSize = 24
)

type IO interface {
	WrapReader(io.Reader) io.Reader
	ByteReader([]byte) Reader
}

type Reader struct {
	r   io.ReadSeeker
	l   int64
	err error
}

func (r *Reader) Read(buf []byte) (int, error) {
	if r.err != nil {
		err := r.err
		r.err = nil
		return 0, err
	}
	return r.r.Read(buf)
}

func (r *Reader) Len() int64 {
	return r.l
}

func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	if r.err != nil {
		return 0, r.err
	}
	return r.r.Seek(offset, whence)
}

type CleartextIO struct{}

func (ci *CleartextIO) WrapReader(r io.Reader) io.Reader {
	return r
}

func (ci *CleartextIO) ByteReader(buf []byte) Reader {
	return Reader{bytes.NewReader(buf), int64(len(buf)), nil}
}

type SecretBoxIO struct {
	SecretKey [32]byte
}

func NewSecretBoxIO(key [32]byte) *SecretBoxIO {
	return &SecretBoxIO{SecretKey: key}
}

func (sb *SecretBoxIO) IsValid() bool {
	var zero [32]byte
	return sb.SecretKey != zero
}

func (sb *SecretBoxIO) makeNonce() ([24]byte, error) {
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	return nonce, err
}

func (sb *SecretBoxIO) WrapReader(r io.Reader) io.Reader {
	if !sb.IsValid() {
		return &Reader{nil, 0, errors.New("SecretBoxIO not properly initialized")}
	}

	allData, err := io.ReadAll(r)
	if err != nil {
		return &Reader{nil, 0, err}
	}

	if len(allData) == 0 {
		return bytes.NewReader(nil)
	}

	if len(allData) < NonceSize {
		return &Reader{nil, 0, errors.New("insufficient data for decryption: missing nonce")}
	}

	var nonce [NonceSize]byte
	copy(nonce[:], allData[:NonceSize])
	encryptedData := allData[NonceSize:]

	bout, ok := secretbox.Open(nil, encryptedData, &nonce, &sb.SecretKey)
	if !ok {
		return &Reader{nil, 0, errors.New("decryption failed: invalid key or corrupted data")}
	}
	return bytes.NewReader(bout)
}

func (sb *SecretBoxIO) ByteReader(msg []byte) Reader {
	if !sb.IsValid() {
		return Reader{nil, 0, errors.New("SecretBoxIO not properly initialized")}
	}

	nonce, err := sb.makeNonce()
	if err != nil {
		return Reader{nil, 0, err}
	}

	out := make([]byte, NonceSize, NonceSize+len(msg)+secretbox.Overhead)
	copy(out, nonce[:])

	out = secretbox.Seal(out, msg, &nonce, &sb.SecretKey)
	return Reader{bytes.NewReader(out), int64(len(out)), nil}
}

var _ io.ReadSeeker = (*Reader)(nil)
