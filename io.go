package cmgs3

import (
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	"log"

	"golang.org/x/crypto/nacl/secretbox"
)

type IO interface {
	Read(io.Reader) io.Reader
	NewReader([]byte) Reader
}

type Reader struct {
	io.Reader
	l int64
}

func (r *Reader) Len() int64 {
	return r.l
}

type CleartextIO struct{}

func (ci *CleartextIO) Read(r io.Reader) io.Reader {
	return r
}

func (ci *CleartextIO) NewReader(buf []byte) Reader {
	return Reader{bytes.NewReader(buf), int64(len(buf))}
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

func (sb *SecretBoxIO) Read(r io.Reader) io.Reader {
	nonce, err := sb.readNonce(r)
	if err != nil {
		log.Printf("error while reading nonce: %v", err)
		return bytes.NewReader(nil)
	}
	log.Printf("nonce in:  %v", nonce)

	buf, _ := ioutil.ReadAll(r)
	bout, ok := secretbox.Open(nil, buf, &nonce, &sb.SecretKey)
	if !ok {
		return bytes.NewReader(nil)
	}
	log.Printf("decrypted: %v", bout)
	return bytes.NewReader(bout)
}

func (sb *SecretBoxIO) NewReader(msg []byte) Reader {
	nonce, err := sb.makeNonce()
	if err != nil {
		log.Printf("Could not make nonce: %v", err)
	}

	log.Printf("nonce out: %v", nonce)
	out := make([]byte, len(nonce))
	copy(out, nonce[:])
	out = secretbox.Seal(out, msg, &nonce, &sb.SecretKey)
	return Reader{bytes.NewReader(out), int64(len(out))}
}
