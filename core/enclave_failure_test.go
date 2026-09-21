package core

import (
	"bytes"
	"testing"
)

// liveBufferCount is a test-only hook exposing how many buffers the core
// allocator currently tracks. A failed Open must leave this unchanged:
// the temporary plaintext buffer and the key view must both be wiped and
// released.
func liveBufferCount() int {
	return len(buffers.copy())
}

// Every single-bit corruption of the ciphertext must produce
// ErrDecryptionFailed, no partial plaintext, and no leaked temporary pages.
func TestOpenWithTamperedCiphertext(t *testing.T) {
	plaintext := []byte("yellow submarine")
	src := make([]byte, len(plaintext))
	copy(src, plaintext)

	e, err := NewEnclave(src)
	if err != nil {
		t.Fatal(err)
	}

	original := make([]byte, len(e.ciphertext))
	copy(original, e.ciphertext)

	before := liveBufferCount()

	for i := range original {
		e.ciphertext[i] ^= 0xff

		buf, err := Open(e)
		if err != ErrDecryptionFailed {
			t.Fatalf("position %d: expected ErrDecryptionFailed; got %v", i, err)
		}
		if buf != nil {
			t.Fatalf("position %d: failed Open returned partial plaintext", i)
		}
		if got := liveBufferCount(); got != before {
			t.Fatalf("position %d: temporary pages not cleaned up on failure (tracked buffers %d -> %d)", i, before, got)
		}

		e.ciphertext[i] = original[i]
	}

	// A failed Open must not modify the enclave.
	if !bytes.Equal(e.ciphertext, original) {
		t.Fatal("ciphertext was modified by Open")
	}

	// The enclave must still open cleanly afterwards.
	buf, err := Open(e)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Data(), plaintext) {
		t.Error("decrypted data does not match original after tamper attempts")
	}
	buf.Destroy()
}

// Truncated ciphertext must never yield plaintext. Truncation within a
// plausible length fails authentication; truncation to an invalid length
// panics safely.
func TestOpenWithTruncatedCiphertext(t *testing.T) {
	e, err := NewEnclave([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}
	original := make([]byte, len(e.ciphertext))
	copy(original, e.ciphertext)

	before := liveBufferCount()

	// Truncate by a single byte: plausible length, must fail authentication.
	e.ciphertext = original[:len(original)-1]
	buf, err := Open(e)
	if err != ErrDecryptionFailed {
		t.Error("expected ErrDecryptionFailed; got", err)
	}
	if buf != nil {
		t.Error("failed Open returned partial plaintext")
	}
	if got := liveBufferCount(); got != before {
		t.Errorf("temporary pages not cleaned up on failure (tracked buffers %d -> %d)", before, got)
	}

	// Truncate to exactly the overhead: invalid length, must panic safely.
	e.ciphertext = original[:Overhead]
	if !panics(func() {
		Open(e)
	}) {
		t.Error("expected panic on ciphertext with invalid length")
	}
}

// Empty payloads must be rejected before any key material is touched.
func TestNewEnclaveRejectsEmptyPayload(t *testing.T) {
	for _, src := range [][]byte{nil, {}} {
		e, err := NewEnclave(src)
		if err != ErrNullEnclave {
			t.Error("expected ErrNullEnclave; got", err)
		}
		if e != nil {
			t.Error("expected nil enclave for empty payload")
		}
	}
}
