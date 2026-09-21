package memguard

import (
	"bytes"
	"sync"
	"testing"
)

// A buffer created from an external byte slice must own a copy of the
// data. Later writes through the source slice must not be observable
// through the protected buffer.
func TestNewBufferFromBytesSourceIsolation(t *testing.T) {
	src := []byte("yellow submarine")
	b := NewBufferFromBytes(src)
	if !b.IsAlive() {
		t.Fatal("buffer should be alive")
	}

	// The constructor wipes the source; write fresh data through it.
	copy(src, []byte("HUNTER2HUNTER2!!"))

	if !b.EqualTo([]byte("yellow submarine")) {
		t.Error("protected contents changed after source slice was modified")
	}
	if bytes.Equal(b.Bytes(), src[:b.Size()]) {
		t.Error("protected buffer aliases the source slice")
	}
	b.Destroy()
}

// Move must transfer the bytes and leave the source handle wiped, while
// the new handle exposes exactly the original bytes.
func TestMoveTransfersAndWipesSource(t *testing.T) {
	src := []byte("yellow submarine")
	want := make([]byte, len(src))
	copy(want, src)

	b := NewBuffer(len(src))
	b.Move(src)

	if !bytes.Equal(src, make([]byte, len(src))) {
		t.Error("source handle still exposes contents after Move")
	}
	if !bytes.Equal(b.Bytes(), want) {
		t.Error("new handle does not hold the original bytes")
	}
	b.Destroy()
}

// Sealing consumes the buffer: the old handle must expose nothing and
// the enclave must yield the original bytes.
func TestSealInvalidatesOldHandle(t *testing.T) {
	data := []byte("yellow submarine")
	b := NewBufferFromBytes(data)

	e := b.Seal()
	if e == nil {
		t.Fatal("expected non-nil enclave")
	}
	if b.IsAlive() {
		t.Error("old handle should be dead after Seal")
	}
	if b.Bytes() != nil || b.Size() != 0 {
		t.Error("old handle still exposes contents after Seal")
	}
	if b.EqualTo([]byte("yellow submarine")) {
		t.Error("old handle still compares equal to the plaintext")
	}

	opened, err := e.Open()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if !opened.EqualTo([]byte("yellow submarine")) {
		t.Error("enclave did not preserve the original bytes")
	}
	opened.Destroy()
}

// Destroy must be idempotent: repeated calls must not double-free or
// resurrect the buffer.
func TestDestroyRepeatedCalls(t *testing.T) {
	b := NewBuffer(32)
	b.Destroy()
	for i := 0; i < 3; i++ {
		b.Destroy()
		if b.IsAlive() {
			t.Fatal("buffer came back to life after repeated Destroy")
		}
		if b.Bytes() != nil || b.Size() != 0 {
			t.Fatal("destroyed buffer still exposes contents")
		}
	}
}

// Purge must be safe to call repeatedly, including when there is nothing
// left to destroy.
func TestPurgeRepeatedCalls(t *testing.T) {
	b := NewBuffer(32)
	e := NewEnclaveRandom(32)
	if e == nil {
		t.Fatal("expected non-nil enclave")
	}

	Purge()
	if b.IsAlive() {
		t.Error("buffer survived Purge")
	}

	// Subsequent purges have nothing to destroy and must not panic.
	Purge()
	Purge()

	if b.IsAlive() {
		t.Error("buffer came back to life after repeated Purge")
	}
	if _, err := e.Open(); err == nil {
		t.Error("enclave should not be decryptable after Purge")
	}

	// The session must still be usable after repeated purges.
	c := NewBuffer(8)
	if !c.IsAlive() {
		t.Error("session unusable after repeated Purge")
	}
	c.Destroy()
}

// Repeated Freeze/Melt cycles must preserve the data and the buffer must
// remain destroyable in either state.
func TestFreezeMeltCyclesPreserveData(t *testing.T) {
	b := NewBuffer(16)
	b.Copy([]byte("yellow submarine"))

	for i := 0; i < 8; i++ {
		b.Freeze()
		if b.IsMutable() {
			t.Fatal("buffer should be immutable after Freeze")
		}
		if !b.EqualTo([]byte("yellow submarine")) {
			t.Fatal("data corrupted after Freeze")
		}
		b.Melt()
		if !b.IsMutable() {
			t.Fatal("buffer should be mutable after Melt")
		}
		if !b.EqualTo([]byte("yellow submarine")) {
			t.Fatal("data corrupted after Melt")
		}
	}

	// Writable again after the final Melt.
	b.Bytes()[0] = 'Y'
	if !b.EqualTo([]byte("Yellow submarine")) {
		t.Fatal("buffer not writable after final Melt")
	}

	// Destroy from the frozen state must also work.
	b.Freeze()
	b.Destroy()
	if b.IsAlive() {
		t.Fatal("buffer should be destroyed")
	}

	// Destroy directly from the molten state.
	c := NewBuffer(16)
	c.Destroy()
	if c.IsAlive() {
		t.Fatal("buffer should be destroyed")
	}
}

// Destroy racing with read-only accessors must converge: readers only
// ever observe the full plaintext or a destroyed buffer, never a data
// race or a partially torn state. Run with -race.
func TestConcurrentDestroyAndReadOnlyAccess(t *testing.T) {
	for iter := 0; iter < 16; iter++ {
		b := NewBufferFromBytes([]byte("yellow submarine"))

		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for {
					alive := b.IsAlive()
					b.Size()
					b.IsMutable()
					if b.EqualTo([]byte("yellow submarine")) {
						if !alive {
							t.Error("destroyed buffer compared equal to plaintext")
						}
						continue
					}
					// Not equal to the plaintext: the buffer must be
					// destroyed. Anything else is a torn read.
					if b.IsAlive() {
						t.Error("live buffer failed to compare equal to its contents")
					}
					return
				}
			}()
		}
		close(start)
		b.Destroy()
		wg.Wait()

		if b.IsAlive() {
			t.Fatal("buffer should be destroyed")
		}
	}
}
