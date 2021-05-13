package s3

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/nacl/secretbox"
)

type IO interface {
	WrapReader(io.Reader) io.Reader
	ByteReader([]byte) Reader
}

type Reader struct {
	r   io.Reader
	l   int64
	err error
}

func (r Reader) Read(buf []byte) (int, error) {
	if r.err != nil {
		tr := r.err
		r.err = nil
		return 0, tr
	}
	return r.r.Read(buf)
}

func (r *Reader) Len() int64 {
	return r.l
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

func (sb *SecretBoxIO) readNonce(r io.Reader) ([24]byte, error) {
	var (
		nonce = make([]byte, 24)
		n     [24]byte
	)
	l, err := r.Read(nonce)
	if l != 24 || err != nil {
		return n, nil
	}
	copy(n[:], nonce)
	return n, nil
}

func (sb *SecretBoxIO) makeNonce() ([24]byte, error) {
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	return nonce, err
}

func (sb *SecretBoxIO) WrapReader(r io.Reader) io.Reader {
	nonce, err := sb.readNonce(r)
	if err != nil {
		return Reader{nil, 0, err}
	}

	buf, _ := ioutil.ReadAll(r)
	bout, ok := secretbox.Open(nil, buf, &nonce, &sb.SecretKey)
	if !ok {
		return Reader{nil, 0, errors.New("decryption failed")}
	}
	return bytes.NewReader(bout)
}

func (sb *SecretBoxIO) ByteReader(msg []byte) Reader {
	nonce, err := sb.makeNonce()
	out := make([]byte, len(nonce))
	copy(out, nonce[:])
	out = secretbox.Seal(out, msg, &nonce, &sb.SecretKey)
	return Reader{bytes.NewReader(out), int64(len(out)), err}
}
