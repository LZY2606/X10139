package core

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/awnumar/memcall"
)

// errInjectedStage is the sentinel failure injected into pipeline stages.
var errInjectedStage = errors.New("injected stage failure")

// stageError annotates a pipeline failure with the stage that caused it
// while preserving the original error for errors.Is/As unwrapping.
type stageError struct {
	stage string
	err   error
}

func (e *stageError) Error() string {
	return fmt.Sprintf("stage %q failed: %s", e.stage, e.err)
}

func (e *stageError) Unwrap() error { return e.err }

// stageOp models one stage of the protected-allocation pipeline.
type stageOp struct {
	name    string
	acquire func() error
	release func()
}

// runStages acquires each stage in order. If a stage fails, every stage
// that already succeeded is released in reverse acquisition order and an
// error identifying the failed stage is returned.
func runStages(stages []stageOp) error {
	acquired := make([]stageOp, 0, len(stages))
	for _, s := range stages {
		if err := s.acquire(); err != nil {
			for i := len(acquired) - 1; i >= 0; i-- {
				acquired[i].release()
			}
			return &stageError{stage: s.name, err: err}
		}
		acquired = append(acquired, s)
	}
	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Pure state-machine test of the staged acquire/rollback contract. It uses
// no syscalls, so it pins the contract on every platform.
func TestStageRollbackStateMachine(t *testing.T) {
	names := []string{"alloc", "lock", "protect"}

	cases := []struct {
		name      string
		failAt    int // -1 means no failure
		wantLog   []string
		wantStage string
	}{
		{"no_failure", -1,
			[]string{"acquire:alloc", "acquire:lock", "acquire:protect"}, ""},
		{"alloc_fails", 0,
			[]string{}, "alloc"},
		{"lock_fails", 1,
			[]string{"acquire:alloc", "release:alloc"}, "lock"},
		{"protect_fails", 2,
			[]string{"acquire:alloc", "acquire:lock", "release:lock", "release:alloc"}, "protect"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var log []string
			stages := make([]stageOp, len(names))
			for i, name := range names {
				i, name := i, name
				stages[i] = stageOp{
					name: name,
					acquire: func() error {
						if i == tc.failAt {
							return errInjectedStage
						}
						log = append(log, "acquire:"+name)
						return nil
					},
					release: func() {
						log = append(log, "release:"+name)
					},
				}
			}

			err := runStages(stages)

			if !equalStrings(log, tc.wantLog) {
				t.Errorf("log mismatch: got %v, want %v", log, tc.wantLog)
			}

			if tc.failAt == -1 {
				if err != nil {
					t.Error("expected nil error; got", err)
				}
				return
			}

			var se *stageError
			if !errors.As(err, &se) {
				t.Fatalf("expected *stageError; got %T (%v)", err, err)
			}
			if se.stage != tc.wantStage {
				t.Errorf("error names stage %q; want %q", se.stage, tc.wantStage)
			}
			if !errors.Is(err, errInjectedStage) {
				t.Error("error does not preserve the original stage failure")
			}
			if !strings.Contains(err.Error(), tc.wantStage) ||
				!strings.Contains(err.Error(), errInjectedStage.Error()) {
				t.Error("error message lost stage information:", err)
			}
		})
	}
}

// The same contract exercised against the real platform adapter: each of
// alloc, lock and protect is failed in turn while the other stages run for
// real, and the resources acquired by earlier stages must be released in
// reverse order.
func TestMemcallStagedFailureRollback(t *testing.T) {
	names := []string{"alloc", "lock", "protect"}

	for failAt := 0; failAt <= len(names); failAt++ {
		failAt := failAt
		name := "no_failure"
		if failAt < len(names) {
			name = names[failAt] + "_fails"
		}

		t.Run(name, func(t *testing.T) {
			var mem []byte
			var log []string

			stages := []stageOp{
				{
					name: "alloc",
					acquire: func() error {
						if failAt == 0 {
							return errInjectedStage
						}
						m, err := memcall.Alloc(2 * pageSize)
						if err != nil {
							return err
						}
						mem = m
						return nil
					},
					release: func() {
						log = append(log, "free")
						_ = memcall.Free(mem)
					},
				},
				{
					name: "lock",
					acquire: func() error {
						if failAt == 1 {
							return errInjectedStage
						}
						return memcall.Lock(mem)
					},
					release: func() {
						log = append(log, "unlock")
						_ = memcall.Unlock(mem)
					},
				},
				{
					name: "protect",
					acquire: func() error {
						if failAt == 2 {
							return errInjectedStage
						}
						return memcall.Protect(mem[:pageSize], memcall.NoAccess())
					},
					release: func() {
						log = append(log, "unprotect")
						_ = memcall.Protect(mem[:pageSize], memcall.ReadWrite())
					},
				},
			}

			err := runStages(stages)

			if failAt < len(names) {
				var se *stageError
				if !errors.As(err, &se) {
					t.Fatalf("expected *stageError; got %T (%v)", err, err)
				}
				if se.stage != names[failAt] {
					t.Errorf("error names stage %q; want %q", se.stage, names[failAt])
				}
				if !errors.Is(err, errInjectedStage) {
					t.Error("error does not preserve the original stage failure")
				}

				// Earlier stages really ran and must have been rolled
				// back in reverse acquisition order.
				var want []string
				switch failAt {
				case 0:
					want = []string{}
				case 1:
					want = []string{"free"}
				case 2:
					want = []string{"unlock", "free"}
				}
				if !equalStrings(log, want) {
					t.Errorf("rollback mismatch: got %v, want %v", log, want)
				}
				return
			}

			// Success path: the region must be usable and then released
			// in reverse order.
			if err != nil {
				t.Fatal("unexpected pipeline failure:", err)
			}
			mem[pageSize] = 0xab // data page must be writable
			if mem[pageSize] != 0xab {
				t.Error("write to data page not reflected")
			}
			for i := len(stages) - 1; i >= 0; i-- {
				stages[i].release()
			}
			if want := []string{"unprotect", "unlock", "free"}; !equalStrings(log, want) {
				t.Errorf("release order mismatch: got %v, want %v", log, want)
			}
		})
	}
}
