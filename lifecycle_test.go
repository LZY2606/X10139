package memguard

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// The protected container must hold its own copy of the data: mutating the
// source slice after construction must never change the protected contents.
func TestNewBufferFromBytesSourceIsolation(t *testing.T) {
	src := []byte("yellow submarine")
	want := make([]byte, len(src))
	copy(want, src)

	b := NewBufferFromBytes(src)
	defer b.Destroy()

	// The constructor wipes the source; overwrite it with fresh data and
	// confirm the protected contents are unaffected.
	for i := range src {
		src[i] = 0x41
	}
	if !b.EqualTo(want) {
		t.Error("protected contents changed after source slice was modified")
	}
	if !bytes.Equal(b.Bytes(), want) {
		t.Error("protected contents do not match the original source data")
	}
}

// Copy must leave the source intact and must not alias it.
func TestCopySourceIsolation(t *testing.T) {
	src := []byte("yellow submarine")
	want := make([]byte, len(src))
	copy(want, src)

	b := NewBuffer(16)
	defer b.Destroy()

	b.Copy(src)
	if !bytes.Equal(src, want) {
		t.Error("Copy must not wipe the source slice")
	}

	for i := range src {
		src[i] ^= 0xff
	}
	if !b.EqualTo(want) {
		t.Error("protected contents changed after source slice was modified")
	}
}

// After a Move the old handle must expose nothing while the new handle
// retains the original bytes.
func TestMoveWipesSourceHandle(t *testing.T) {
	src := []byte("yellow submarine")
	want := make([]byte, len(src))
	copy(want, src)

	b := NewBuffer(16)
	defer b.Destroy()

	b.Move(src)

	// The old handle must no longer expose the contents.
	if !bytes.Equal(src, make([]byte, 16)) {
		t.Error("source handle still exposes data after Move")
	}
	// The new handle must hold the original bytes.
	if !b.EqualTo(want) {
		t.Error("new handle does not hold the original bytes after Move")
	}
	// Writing to the old handle afterwards must not leak into the new one.
	for i := range src {
		src[i] = 0x7a
	}
	if !b.EqualTo(want) {
		t.Error("protected contents changed after old handle was reused")
	}
}

// Repeated Freeze/Melt cycles must preserve the data and the buffer must
// remain destroyable afterwards.
func TestFreezeMeltCyclesPreserveData(t *testing.T) {
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}

	b := NewBuffer(32)
	b.Copy(data)

	for i := 0; i < 8; i++ {
		b.Freeze()
		b.Freeze() // idempotent
		if b.IsMutable() {
			t.Fatalf("cycle %d: buffer is mutable after Freeze", i)
		}
		if !b.EqualTo(data) {
			t.Fatalf("cycle %d: data corrupted while frozen", i)
		}

		b.Melt()
		b.Melt() // idempotent
		if !b.IsMutable() {
			t.Fatalf("cycle %d: buffer is immutable after Melt", i)
		}

		// Mutate through the buffer to prove writability, keeping the
		// reference copy in sync.
		b.Bytes()[i] ^= 0xff
		data[i] ^= 0xff
		if !b.EqualTo(data) {
			t.Fatalf("cycle %d: write after Melt not reflected", i)
		}
	}

	b.Freeze()
	if !b.EqualTo(data) {
		t.Error("data corrupted after final Freeze")
	}

	// The buffer must still be cleanly destroyable.
	b.Destroy()
	if b.IsAlive() {
		t.Error("buffer still alive after Destroy")
	}
	b.Destroy() // repeated Destroy must not double-free
	if b.IsAlive() || b.Size() != 0 {
		t.Error("buffer state changed after repeated Destroy")
	}
}

// Destroy and Purge must be safe to call repeatedly: no double-free, no
// panic, and the session must remain usable afterwards.
func TestDestroyAndPurgeIdempotent(t *testing.T) {
	b := NewBufferFromBytes([]byte("yellow submarine"))
	b.Destroy()
	b.Destroy() // must not double-free
	if b.IsAlive() {
		t.Error("buffer came back to life after repeated Destroy")
	}
	if b.Bytes() != nil || b.Size() != 0 {
		t.Error("destroyed buffer still exposes a data handle")
	}

	c := NewBufferRandom(64)
	Purge()
	if c.IsAlive() {
		t.Error("Purge did not destroy the buffer")
	}
	Purge() // repeated Purge on an empty session must not panic
	if c.IsAlive() {
		t.Error("buffer came back to life after repeated Purge")
	}

	// The session must still be fully usable.
	d := NewBufferFromBytes([]byte("submarine yellow"))
	if !d.EqualTo([]byte("submarine yellow")) {
		t.Error("session unusable after repeated Purge")
	}
	d.Destroy()
}

// Destroy racing with read-only accessors must converge to the destroyed
// state without data races. Run with -race for this to be meaningful.
func TestConcurrentDestroyWithReadOnlyAccess(t *testing.T) {
	for iter := 0; iter < 32; iter++ {
		want := []byte("concurrent read-only probe")
		src := make([]byte, len(want))
		copy(src, want)
		b := NewBufferFromBytes(src)

		stop := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					if !b.IsAlive() {
						return
					}
					// Read-only accessors that hold the read lock.
					b.EqualTo(want)
					b.IsMutable()
				}
			}()
		}

		b.Destroy()
		close(stop)

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("iteration", iter, ": readers did not converge after Destroy")
		}

		// After convergence the destroyed state must be stable.
		if b.IsAlive() {
			t.Fatal("iteration", iter, ": buffer alive after Destroy")
		}
		if b.EqualTo(want) {
			t.Fatal("iteration", iter, ": destroyed buffer compared equal")
		}
		if b.Size() != 0 {
			t.Fatal("iteration", iter, ": destroyed buffer has non-zero size")
		}
	}
}
