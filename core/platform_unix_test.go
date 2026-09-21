//go:build unix

package core

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/awnumar/memcall"
)

// Real syscall-level contract checks for the platform adapter. These run
// only on unix platforms; other platforms are covered by the portable
// state-machine tests in platform_test.go.

func TestMemcallAllocContract(t *testing.T) {
	mem, err := memcall.Alloc(2 * pageSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(mem) != 2*pageSize {
		t.Error("allocated region has wrong length")
	}
	if uintptr(unsafe.Pointer(&mem[0]))%uintptr(pageSize) != 0 {
		t.Error("allocated region is not page aligned")
	}
	// Freshly allocated memory must be zero-filled, never remnant data.
	for i := range mem {
		if mem[i] != 0 {
			t.Fatal("allocated region is not zero-filled")
		}
	}
	// The region must be readable and writable.
	mem[0] = 0xab
	mem[len(mem)-1] = 0xcd
	if mem[0] != 0xab || mem[len(mem)-1] != 0xcd {
		t.Error("allocated region is not read-write")
	}
	if err := memcall.Free(mem); err != nil {
		t.Error("failed to free region:", err)
	}
}

func TestMemcallAllocFailurePreservesStageInfo(t *testing.T) {
	// A zero-length mapping is rejected by the kernel (EINVAL).
	mem, err := memcall.Alloc(0)
	if err == nil {
		_ = memcall.Free(mem)
		t.Fatal("expected error for zero-length allocation")
	}
	if mem != nil {
		t.Error("failed allocation returned a non-nil region")
	}
	if !strings.Contains(err.Error(), "could not allocate") {
		t.Error("error lost allocation stage information:", err)
	}
}

func TestMemcallLockUnlockRoundTrip(t *testing.T) {
	mem, err := memcall.Alloc(pageSize)
	if err != nil {
		t.Fatal(err)
	}
	defer memcall.Free(mem)

	if err := memcall.Lock(mem); err != nil {
		t.Error("failed to lock region:", err)
	}
	if err := memcall.Unlock(mem); err != nil {
		t.Error("failed to unlock region:", err)
	}
}

func TestMemcallProtectRoundTripPreservesData(t *testing.T) {
	mem, err := memcall.Alloc(pageSize)
	if err != nil {
		t.Fatal(err)
	}
	defer memcall.Free(mem)

	pattern := make([]byte, pageSize)
	for i := range pattern {
		pattern[i] = byte(i)
	}
	copy(mem, pattern)

	if err := memcall.Protect(mem, memcall.ReadOnly()); err != nil {
		t.Fatal("failed to make region read-only:", err)
	}
	// The data must still be readable and intact.
	for i := range mem {
		if mem[i] != pattern[i] {
			t.Fatal("data corrupted by protection change")
		}
	}
	if err := memcall.Protect(mem, memcall.ReadWrite()); err != nil {
		t.Fatal("failed to restore read-write access:", err)
	}
	mem[0] ^= 0xff // must be writable again
	if mem[0] != pattern[0]^0xff {
		t.Error("region not writable after restoring read-write access")
	}
}

func TestMemcallProtectInvalidFlag(t *testing.T) {
	mem, err := memcall.Alloc(pageSize)
	if err != nil {
		t.Fatal(err)
	}
	defer memcall.Free(mem)

	// The zero value is not a defined protection flag.
	err = memcall.Protect(mem, memcall.MemoryProtectionFlag{})
	if err == nil {
		t.Fatal("expected error for undefined protection flag")
	}
	if err.Error() != memcall.ErrInvalidFlag {
		t.Error("expected ErrInvalidFlag; got", err)
	}
}
