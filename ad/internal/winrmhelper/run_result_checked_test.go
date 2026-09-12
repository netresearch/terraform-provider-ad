package winrmhelper

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// discardedRun matches a PSCommand.Run whose result is thrown away.
//
// `result, err :=` keeps the exit code reachable; `_, err :=` does not, and Go
// accepts both, so neither the compiler, go vet nor golangci-lint says anything.
var discardedRun = regexp.MustCompile(`_,\s*err\s*:?=\s*\w+\.Run\(`)

// TestNoRunResultIsDiscarded is a source guard, and it exists because this exact
// defect happened twice independently in this package.
//
// PSCommand.Run returns an error only for transport failures. A PowerShell
// command that Active Directory refuses — deleting an account protected from
// accidental deletion, deleting a GPO without the rights — returns no error and
// a non-zero ExitCode. Discarding the result therefore turns a refused
// destructive operation into a reported success, and Terraform drops the
// resource from state while the object still exists in the directory.
//
// What this proves and what it does not: it proves no call site in this package
// throws the result away. It does not prove the exit code is then checked
// correctly, which needs a reachable domain.
func TestNoRunResultIsDiscarded(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}

	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++

		body, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}

		for i, line := range strings.Split(string(body), "\n") {
			if discardedRun.MatchString(line) {
				t.Errorf("%s:%d discards the PSCommand.Run result:\n\t%s\n"+
					"Assign it and check ExitCode — Run returns no error for a command the directory refuses.",
					name, i+1, strings.TrimSpace(line))
			}
		}
	}

	// A guard that silently inspects nothing passes forever.
	if checked == 0 {
		t.Fatal("no source files were inspected")
	}
	t.Logf("inspected %d source files", checked)
}
