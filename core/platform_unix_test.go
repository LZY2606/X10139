//go:build !windows

package core

import (
	"testing"

	"github.com/awnumar/memcall"
)

// Unix-specific adapter behaviour: freeing the same region twice must
// surface an error from the second call rather than crashing or
// succeeding silently.
func TestMemcallDoubleFreeFails(t *testing.T) {
	b, err := memcall.Alloc(pageSize)
	if err != nil {
		t.Fatal("alloc failed:", err)
	}
	if err := memcall.Free(b); err != nil {
		t.Fatal("first free failed:", err)
	}
	if err := memcall.Free(b); err == nil {
		t.Error("expected error from double free")
	}
}
