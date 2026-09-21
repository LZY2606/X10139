package memguard

import (
	"testing"

	"github.com/awnumar/memguard/core"
)

// Empty payloads must be rejected with a nil Enclave.
func TestNewEnclaveRejectsEmptyPayload(t *testing.T) {
	if e := NewEnclave([]byte{}); e != nil {
		t.Error("expected nil enclave for empty payload")
	}
	if e := NewEnclave(nil); e != nil {
		t.Error("expected nil enclave for nil payload")
	}
}

// An Enclave must be reusable: consecutive Open calls each return an
// independent, correct, immutable buffer.
func TestEnclaveConsecutiveOpens(t *testing.T) {
	src := []byte("yellow submarine")
	want := make([]byte, len(src))
	copy(want, src)

	e := NewEnclave(src)
	if e == nil {
		t.Fatal("got nil enclave")
	}

	var opened []*LockedBuffer
	for i := 0; i < 3; i++ {
		b, err := e.Open()
		if err != nil {
			t.Fatalf("open %d: unexpected error: %v", i, err)
		}
		if b == nil {
			t.Fatalf("open %d: got nil buffer", i)
		}
		if !b.EqualTo(want) {
			t.Fatalf("open %d: data does not match original", i)
		}
		if b.IsMutable() {
			t.Fatalf("open %d: opened buffer must be immutable", i)
		}
		opened = append(opened, b)
	}

	// Destroying one handle must not affect the others.
	opened[0].Destroy()
	for _, b := range opened[1:] {
		if !b.IsAlive() || !b.EqualTo(want) {
			t.Error("destroying one opened handle affected another")
		}
		b.Destroy()
	}

	// The enclave itself must still be openable.
	b, err := e.Open()
	if err != nil {
		t.Fatal("enclave not reusable after consecutive opens:", err)
	}
	if !b.EqualTo(want) {
		t.Error("data does not match original after consecutive opens")
	}
	b.Destroy()
}

// A failed Open (authentication failure injected by re-keying the session)
// must return the decryption error and no buffer carrying partial plaintext.
func TestEnclaveOpenFailureReturnsNoPlaintext(t *testing.T) {
	e := NewEnclave([]byte("yellow submarine"))
	if e == nil {
		t.Fatal("got nil enclave")
	}

	Purge() // re-keys the session, invalidating the enclave's ciphertext

	b, err := e.Open()
	if err != core.ErrDecryptionFailed {
		t.Error("expected ErrDecryptionFailed; got", err)
	}
	if b != nil {
		b.Destroy()
		t.Error("failed Open must not return partial plaintext")
	}
}
