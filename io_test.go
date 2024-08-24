package s3

import (
	"bytes"
	"io"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	secret := []byte("12345678123456781234567812345678")
	var sbuf [32]byte

	copy(sbuf[:], secret)

	sb := SecretBoxIO{
		SecretKey: sbuf,
	}

	msg := []byte("This is a very important message that shall be encrypted...")
	r := sb.ByteReader(msg)

	buf, err := io.ReadAll(r)
	if err != nil {
		t.Errorf("encrypting failed: %v", err)
	}

	w := bytes.NewReader(buf)
	wb := sb.WrapReader(w)

	buf, err = io.ReadAll(wb)
	if err != nil {
		t.Errorf("decrypting failed: %v", err)
	}

	if string(buf) != string(msg) {
		t.Errorf("did not decrypt, got: %s", buf)
	}
}

func TestIOWrap(t *testing.T) {
	empty := bytes.NewReader(nil)

	sb := SecretBoxIO{}
	wr := sb.WrapReader(empty)

	buf, err := io.ReadAll(wr)
	if err != nil {
		t.Errorf("reading failed: %s", err)
	}
	if len(buf) != 0 {
		t.Errorf("Buffer should be empty, got: %v", buf)
	}
}
