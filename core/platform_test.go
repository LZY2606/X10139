package core

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/awnumar/memcall"
)

// This file pins down the contract that the platform adaptation layer
// (memcall) and its callers must satisfy when acquiring protected
// memory: resources are acquired in a fixed order (alloc, lock,
// protect) and, if any stage fails, everything acquired so far is
// released in the exact reverse order, with the error identifying the
// failing stage. The state machine below is platform-neutral so the
// contract holds on every target; platform-specific files execute the
// real syscalls where available.

// memOps abstracts the platform memory primitives so failures can be
// injected deterministically in tests.
type memOps interface {
	Alloc(n int) ([]byte, error)
	Lock(b []byte) error
	Protect(b []byte) error
	Unlock(b []byte) error
	Free(b []byte) error
}

// stageError wraps the underlying error with the stage that produced it.
type stageError struct {
	stage string
	err   error
}

func (e *stageError) Error() string { return fmt.Sprintf("%s: %s", e.stage, e.err) }
func (e *stageError) Unwrap() error { return e.err }

// guardedAlloc acquires a protected region. On failure at any stage it
// releases previously acquired resources in reverse order and returns a
// stageError identifying the failing stage.
func guardedAlloc(ops memOps, size int) ([]byte, error) {
	b, err := ops.Alloc(size)
	if err != nil {
		return nil, &stageError{"alloc", err}
	}
	if err := ops.Lock(b); err != nil {
		ops.Free(b)
		return nil, &stageError{"lock", err}
	}
	if err := ops.Protect(b); err != nil {
		ops.Unlock(b)
		ops.Free(b)
		return nil, &stageError{"protect", err}
	}
	return b, nil
}

// fakeOps records every call and fails at a configurable stage.
type fakeOps struct {
	failAt string
	calls  []string
	mem    []byte
}

func (f *fakeOps) record(name string) error {
	f.calls = append(f.calls, name)
	if f.failAt == name {
		return fmt.Errorf("injected %s failure", name)
	}
	return nil
}

func (f *fakeOps) Alloc(n int) ([]byte, error) {
	if err := f.record("alloc"); err != nil {
		return nil, err
	}
	f.mem = make([]byte, n)
	return f.mem, nil
}

func (f *fakeOps) Lock(b []byte) error    { return f.record("lock") }
func (f *fakeOps) Protect(b []byte) error { return f.record("protect") }
func (f *fakeOps) Unlock(b []byte) error  { return f.record("unlock") }
func (f *fakeOps) Free(b []byte) error    { return f.record("free") }

func TestGuardedAllocStagedFailures(t *testing.T) {
	cases := []struct {
		name         string
		failAt       string
		wantCalls    []string
		wantErrStage string
	}{
		{"alloc fails", "alloc", []string{"alloc"}, "alloc"},
		{"lock fails", "lock", []string{"alloc", "lock", "free"}, "lock"},
		{"protect fails", "protect", []string{"alloc", "lock", "protect", "unlock", "free"}, "protect"},
		{"no failure", "", []string{"alloc", "lock", "protect"}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ops := &fakeOps{failAt: tc.failAt}
			b, err := guardedAlloc(ops, pageSize)

			if len(ops.calls) != len(tc.wantCalls) {
				t.Fatalf("call sequence %v, want %v", ops.calls, tc.wantCalls)
			}
			for i := range tc.wantCalls {
				if ops.calls[i] != tc.wantCalls[i] {
					t.Fatalf("call sequence %v, want %v", ops.calls, tc.wantCalls)
				}
			}

			if tc.wantErrStage == "" {
				if err != nil {
					t.Fatalf("expected success; got %v", err)
				}
				if b == nil {
					t.Fatal("expected non-nil region on success")
				}
				return
			}

			if err == nil {
				t.Fatal("expected error; got nil")
			}
			if b != nil {
				t.Error("expected nil region on failure")
			}
			var se *stageError
			if !errors.As(err, &se) {
				t.Fatalf("error does not preserve stage information: %v", err)
			}
			if se.stage != tc.wantErrStage {
				t.Errorf("error stage %q, want %q", se.stage, tc.wantErrStage)
			}
			if !strings.Contains(err.Error(), "injected "+tc.wantErrStage+" failure") {
				t.Errorf("error does not wrap the original cause: %v", err)
			}
		})
	}
}

// The real platform adapter must satisfy the same acquire/release
// contract on the host running the tests: a full alloc, lock, protect,
// unlock, free round-trip succeeds and freshly allocated memory is
// zeroed.
func TestMemcallRoundTrip(t *testing.T) {
	b, err := memcall.Alloc(pageSize)
	if err != nil {
		t.Fatal("alloc failed:", err)
	}
	if len(b) != pageSize {
		t.Error("allocated region has wrong size")
	}
	if !bytes.Equal(b, make([]byte, pageSize)) {
		t.Error("freshly allocated memory is not zeroed")
	}

	if err := memcall.Lock(b); err != nil {
		memcall.Free(b)
		t.Fatal("lock failed:", err)
	}

	b[0] = 0x41
	if err := memcall.Protect(b, memcall.ReadOnly()); err != nil {
		memcall.Unlock(b)
		memcall.Free(b)
		t.Fatal("protect read-only failed:", err)
	}
	if b[0] != 0x41 {
		t.Error("data not readable after protect")
	}

	if err := memcall.Protect(b, memcall.ReadWrite()); err != nil {
		memcall.Unlock(b)
		memcall.Free(b)
		t.Fatal("protect read-write failed:", err)
	}
	b[0] = 0

	if err := memcall.Unlock(b); err != nil {
		memcall.Free(b)
		t.Fatal("unlock failed:", err)
	}
	if err := memcall.Free(b); err != nil {
		t.Fatal("free failed:", err)
	}
}

// The adapter must report invalid protection flags as errors instead of
// silently succeeding or panicking.
func TestMemcallProtectInvalidFlag(t *testing.T) {
	b, err := memcall.Alloc(pageSize)
	if err != nil {
		t.Fatal("alloc failed:", err)
	}
	defer memcall.Free(b)

	err = memcall.Protect(b, memcall.MemoryProtectionFlag{})
	if err == nil {
		t.Error("expected error for undefined protection flag")
	}
	if !strings.Contains(err.Error(), "memcall") {
		t.Error("error does not identify the platform layer:", err)
	}
}
