package core

import (
	"bytes"
	"testing"
)

// Repeated Freeze/Melt cycles at the core allocator level must preserve the
// data, and the buffer must remain destroyable afterwards.
func TestBufferFreezeMeltCyclesPreserveData(t *testing.T) {
	b, err := NewBuffer(64)
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i)
	}
	Copy(b.Data(), data)

	for i := 0; i < 8; i++ {
		b.Freeze()
		b.Freeze() // idempotent
		if b.Mutable() {
			t.Fatalf("cycle %d: buffer is mutable after Freeze", i)
		}
		if !Equal(b.Data(), data) {
			t.Fatalf("cycle %d: data corrupted while frozen", i)
		}

		b.Melt()
		b.Melt() // idempotent
		if !b.Mutable() {
			t.Fatalf("cycle %d: buffer is immutable after Melt", i)
		}

		// Mutate through the buffer to prove writability.
		b.Data()[i] ^= 0xff
		data[i] ^= 0xff
		if !Equal(b.Data(), data) {
			t.Fatalf("cycle %d: write after Melt not reflected", i)
		}
	}

	b.Freeze()
	if !Equal(b.Data(), data) {
		t.Error("data corrupted after final Freeze")
	}

	b.Destroy()
	if b.Alive() {
		t.Error("buffer still alive after Destroy")
	}
	b.Destroy() // repeated Destroy must not double-free
	if b.Alive() {
		t.Error("buffer came back to life after repeated Destroy")
	}
}

// Purge must destroy every tracked buffer, and calling it again on an empty
// session must not panic or double-free. The session must remain usable.
func TestPurgeIsIdempotent(t *testing.T) {
	b1, err := NewBuffer(32)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := NewBuffer(64)
	if err != nil {
		t.Fatal(err)
	}

	Purge()
	if b1.Alive() || b2.Alive() {
		t.Error("Purge did not destroy all buffers")
	}
	if n := liveBufferCount(); n != 0 {
		t.Error("expected no tracked buffers after Purge; got", n)
	}

	Purge() // repeated Purge must not panic or double-free
	if n := liveBufferCount(); n != 0 {
		t.Error("expected no tracked buffers after repeated Purge; got", n)
	}

	// The session must still be fully usable.
	e, err := NewEnclave([]byte("yellow submarine"))
	if err != nil {
		t.Fatal("session unusable after repeated Purge:", err)
	}
	buf, err := Open(e)
	if err != nil {
		t.Fatal("session unusable after repeated Purge:", err)
	}
	if !bytes.Equal(buf.Data(), []byte("yellow submarine")) {
		t.Error("decrypted data does not match after repeated Purge")
	}
	buf.Destroy()
}
