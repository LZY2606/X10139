//go:build windows

package core

import (
	"testing"
)

// Windows builds cannot be exercised here, so this file keeps the
// platform-neutral acquire/release contract compiling and running under
// the windows build tag. The real syscall round-trip lives in the
// untagged platform_test.go and runs wherever tests execute.
func TestGuardedAllocContractWindows(t *testing.T) {
	ops := &fakeOps{failAt: "protect"}
	if _, err := guardedAlloc(ops, 4096); err == nil {
		t.Error("expected injected failure to propagate")
	}
	want := []string{"alloc", "lock", "protect", "unlock", "free"}
	if len(ops.calls) != len(want) {
		t.Fatalf("call sequence %v, want %v", ops.calls, want)
	}
	for i := range want {
		if ops.calls[i] != want[i] {
			t.Fatalf("call sequence %v, want %v", ops.calls, want)
		}
	}
}
