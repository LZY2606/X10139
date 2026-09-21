package core

import (
	"bytes"
	"testing"
)

// snapshotBuffers returns the set of buffers currently tracked by the
// global buffer list.
func snapshotBuffers() map[*Buffer]bool {
	set := make(map[*Buffer]bool)
	for _, b := range buffers.copy() {
		set[b] = true
	}
	return set
}

// Tampering with any part of the ciphertext must make Open fail without
// returning any plaintext.
func TestOpenTamperedCiphertext(t *testing.T) {
	e, err := NewEnclave([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	// Flip one bit in the nonce, the authenticator and the body.
	for _, pos := range []int{0, 24, len(e.ciphertext) - 1} {
		orig := e.ciphertext[pos]
		e.ciphertext[pos] ^= 0xff

		b, err := Open(e)
		if err != ErrDecryptionFailed {
			t.Errorf("position %d: expected ErrDecryptionFailed; got %v", pos, err)
		}
		if b != nil {
			t.Errorf("position %d: expected nil buffer on failure", pos)
		}

		e.ciphertext[pos] = orig
	}

	// The restored enclave must still open correctly.
	b, err := Open(e)
	if err != nil {
		t.Fatal("restored enclave failed to open:", err)
	}
	if !bytes.Equal(b.Data(), []byte("yellow submarine")) {
		t.Error("data mismatch after restoring ciphertext")
	}
	b.Destroy()
}

// Truncating the ciphertext must not yield partial plaintext.
func TestOpenTruncatedCiphertext(t *testing.T) {
	e, err := NewEnclave([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	// Remove a single byte from the sealed body.
	truncated := &Enclave{ciphertext: e.ciphertext[:len(e.ciphertext)-1]}
	b, err := Open(truncated)
	if err != ErrDecryptionFailed {
		t.Error("expected ErrDecryptionFailed; got", err)
	}
	if b != nil {
		t.Error("expected nil buffer on failure")
	}

	// A ciphertext too short to even hold the overhead must panic safely
	// rather than allocate a negative-size buffer.
	defer func() {
		if recover() == nil {
			t.Error("expected panic on ciphertext shorter than overhead")
		}
	}()
	Open(&Enclave{ciphertext: e.ciphertext[:Overhead-1]})
}

// Empty payloads are rejected at construction time.
func TestNewEnclaveEmptyPayload(t *testing.T) {
	for _, in := range [][]byte{nil, {}} {
		e, err := NewEnclave(in)
		if err != ErrNullEnclave {
			t.Error("expected ErrNullEnclave; got", err)
		}
		if e != nil {
			t.Error("expected nil enclave for empty payload")
		}
	}
}

// An enclave is reusable: consecutive Open calls each return the full
// plaintext in an independent buffer.
func TestOpenConsecutive(t *testing.T) {
	e, err := NewEnclave([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	first, err := Open(e)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(e)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first.Data(), []byte("yellow submarine")) {
		t.Error("first open returned wrong data")
	}
	if !bytes.Equal(second.Data(), []byte("yellow submarine")) {
		t.Error("second open returned wrong data")
	}

	// Destroying the first result must not affect the second.
	first.Destroy()
	if !bytes.Equal(second.Data(), []byte("yellow submarine")) {
		t.Error("second open affected by destruction of first")
	}
	second.Destroy()

	// The enclave itself is untouched and still opens.
	third, err := Open(e)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(third.Data(), []byte("yellow submarine")) {
		t.Error("enclave state changed across opens")
	}
	third.Destroy()
}

// When authentication fails during Open, no partial plaintext may be
// returned and every temporary allocation (the output buffer and the key
// view) must be wiped and released, not leaked into the global list.
func TestOpenFailureReleasesTemporaryBuffers(t *testing.T) {
	e, err := NewEnclave([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the ciphertext to force an authentication failure.
	for i := range e.ciphertext {
		e.ciphertext[i] ^= 0xff
	}

	before := snapshotBuffers()

	b, err := Open(e)
	if err != ErrDecryptionFailed {
		t.Fatal("expected ErrDecryptionFailed; got", err)
	}
	if b != nil {
		t.Fatal("expected nil buffer on failure")
	}

	after := snapshotBuffers()

	for buf := range after {
		if !before[buf] {
			t.Error("temporary buffer leaked into global list after failed Open")
		}
	}
	for buf := range before {
		if !after[buf] && buf.Alive() {
			t.Error("pre-existing buffer vanished from global list")
		}
	}
}

// A failed Decrypt must leave the caller's output buffer untouched: no
// partial plaintext may be written into it.
func TestDecryptFailureLeavesOutputUntouched(t *testing.T) {
	key := make([]byte, 32)
	if err := Scramble(key); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := Encrypt([]byte("yellow submarine"), key)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]func() []byte{
		"tampered ciphertext": func() []byte {
			c := make([]byte, len(ciphertext))
			copy(c, ciphertext)
			c[len(c)-1] ^= 0xff
			return c
		},
		"truncated ciphertext": func() []byte {
			return ciphertext[:len(ciphertext)-1]
		},
		"wrong key ciphertext": func() []byte {
			other := make([]byte, 32)
			if err := Scramble(other); err != nil {
				t.Fatal(err)
			}
			c, err := Encrypt([]byte("yellow submarine"), other)
			if err != nil {
				t.Fatal(err)
			}
			Wipe(other)
			return c
		},
	}

	for name, makeCiphertext := range cases {
		output := bytes.Repeat([]byte{0xaa}, len(ciphertext)-Overhead)
		n, err := Decrypt(makeCiphertext(), key, output)
		if err != ErrDecryptionFailed {
			t.Errorf("%s: expected ErrDecryptionFailed; got %v", name, err)
		}
		if n != 0 {
			t.Errorf("%s: expected zero plaintext length; got %d", name, n)
		}
		if !bytes.Equal(output, bytes.Repeat([]byte{0xaa}, len(output))) {
			t.Errorf("%s: output buffer modified on failure", name)
		}
	}
	Wipe(key)
}
