package s3

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

var (
	testKey32  = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	testKeyStr = "12345678901234567890123456789012"
)

func createTestSecretBoxIO() *SecretBoxIO {
	sb := &SecretBoxIO{}
	copy(sb.SecretKey[:], []byte(testKeyStr))
	return sb
}

func assertNoError(t *testing.T, err error, operation string) {
	if err != nil {
		t.Errorf("%s failed: %v", operation, err)
	}
}

func assertError(t *testing.T, err error, expectedMsg, operation string) {
	if err == nil || !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("%s should fail with '%s', got error: %v", operation, expectedMsg, err)
	}
}

func TestNewSecretBoxIO(t *testing.T) {
	sb := NewSecretBoxIO(testKey32)
	if sb == nil {
		t.Error("NewSecretBoxIO() returned nil")
		return
	}
	if sb.SecretKey != testKey32 {
		t.Error("NewSecretBoxIO() did not set key correctly")
	}
}

func TestSecretBoxIO_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		sb    *SecretBoxIO
		valid bool
	}{
		{
			name:  "uninitialized (zero key)",
			sb:    &SecretBoxIO{},
			valid: false,
		},
		{
			name: "valid key",
			sb: &SecretBoxIO{
				SecretKey: testKey32,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sb.IsValid(); got != tt.valid {
				t.Errorf("SecretBoxIO.IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestSecretBoxIO_Operations(t *testing.T) {
	t.Run("encrypt decrypt roundtrip", func(t *testing.T) {
		sb := createTestSecretBoxIO()
		msg := []byte("This is a very important message that shall be encrypted...")
		r := sb.ByteReader(msg)

		buf, err := io.ReadAll(&r)
		assertNoError(t, err, "encrypting")

		w := bytes.NewReader(buf)
		wb := sb.WrapReader(w)

		buf, err = io.ReadAll(wb)
		assertNoError(t, err, "decrypting")

		if string(buf) != string(msg) {
			t.Errorf("did not decrypt, got: %s", buf)
		}
	})

	t.Run("empty input handling", func(t *testing.T) {
		sb := createTestSecretBoxIO()

		wr := sb.WrapReader(bytes.NewReader(nil))
		buf, err := io.ReadAll(wr)
		assertNoError(t, err, "WrapReader with empty input")
		if len(buf) != 0 {
			t.Errorf("Buffer should be empty, got: %v", buf)
		}

		reader := sb.ByteReader([]byte{})
		_, err = io.ReadAll(&reader)
		assertNoError(t, err, "ByteReader with empty input")
	})

	t.Run("valid operations", func(t *testing.T) {
		sb := createTestSecretBoxIO()

		reader := sb.ByteReader([]byte("test message"))
		_, err := io.ReadAll(&reader)
		assertNoError(t, err, "ByteReader with valid input")
	})
}

func TestSecretBoxIO_ErrorCases(t *testing.T) {
	t.Run("uninitialized SecretBoxIO", func(t *testing.T) {
		sb := &SecretBoxIO{}

		wr := sb.WrapReader(bytes.NewReader([]byte("test")))
		_, err := io.ReadAll(wr)
		assertError(t, err, "not properly initialized", "WrapReader")

		reader := sb.ByteReader([]byte("test"))
		_, err = io.ReadAll(&reader)
		assertError(t, err, "not properly initialized", "ByteReader")
	})

	t.Run("insufficient data for decryption", func(t *testing.T) {
		sb := &SecretBoxIO{SecretKey: testKey32}
		wr := sb.WrapReader(bytes.NewReader([]byte("short"))) // Less than 24 bytes
		_, err := io.ReadAll(wr)
		assertError(t, err, "insufficient data for decryption", "decryption")
	})
}

func TestCleartextIO(t *testing.T) {
	ci := &CleartextIO{}
	testData := []byte("plain text data")

	reader := ci.ByteReader(testData)
	result, err := io.ReadAll(&reader)
	if err != nil {
		t.Errorf("CleartextIO.ByteReader() error = %v", err)
	}
	if !bytes.Equal(result, testData) {
		t.Errorf("CleartextIO.ByteReader() = %v, want %v", result, testData)
	}

	input := bytes.NewReader(testData)
	wrapped := ci.WrapReader(input)
	result, err = io.ReadAll(wrapped)
	if err != nil {
		t.Errorf("CleartextIO.WrapReader() error = %v", err)
	}
	if !bytes.Equal(result, testData) {
		t.Errorf("CleartextIO.WrapReader() = %v, want %v", result, testData)
	}
}

func TestReader(t *testing.T) {
	t.Run("normal operations", func(t *testing.T) {
		testData := []byte("test data")
		reader := Reader{
			r: bytes.NewReader(testData),
			l: int64(len(testData)),
		}

		if reader.Len() != int64(len(testData)) {
			t.Errorf("Reader.Len() = %d, want %d", reader.Len(), len(testData))
		}

		buf := make([]byte, len(testData))
		n, err := reader.Read(buf)
		assertNoError(t, err, "Reader.Read()")
		if n != len(testData) {
			t.Errorf("Reader.Read() n = %d, want %d", n, len(testData))
		}
		if !bytes.Equal(buf, testData) {
			t.Errorf("Reader.Read() buf = %v, want %v", buf, testData)
		}
	})

	t.Run("error handling", func(t *testing.T) {
		testErr := errors.New("test error")
		reader := Reader{
			r:   bytes.NewReader(nil),
			l:   0,
			err: testErr,
		}

		buf := make([]byte, 10)
		n, err := reader.Read(buf)
		if err != testErr {
			t.Errorf("Reader.Read() error = %v, want %v", err, testErr)
		}
		if n != 0 {
			t.Errorf("Reader.Read() n = %d, want 0", n)
		}
	})
}
