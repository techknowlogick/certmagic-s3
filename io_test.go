package cmgs3

import (
	"bytes"
	"io/ioutil"
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
	r := sb.NewReader(msg)

	buf, err := ioutil.ReadAll(r)
	if err != nil {
		t.Errorf("encrypting failed: %v", err)
	}

	w := bytes.NewReader(buf)
	wb := sb.Read(w)

	buf, err = ioutil.ReadAll(wb)
	if err != nil {
		t.Errorf("decrypting failed: %v", err)
	}

	if string(buf) != string(msg) {
		t.Errorf("did not decrypt, got: %s", buf)
	}
}
