package winrmhelper

import (
	"errors"
	"strings"
	"testing"
)

// TestCheckDeleteResult covers the case the delete paths used to get wrong: the
// directory refuses the removal, PSCommand.Run reports no error, and only the
// exit code says so. Treating that as success let Terraform drop a resource from
// state while the object was still in the directory.
func TestCheckDeleteResult(t *testing.T) {
	const alreadyGone = "ADIdentityNotFoundException"

	t.Run("refused removal is an error", func(t *testing.T) {
		res := &PSCommandResult{ExitCode: 1, StdErr: "Access is denied"}

		err := CheckDeleteResult(res, nil, alreadyGone, "user")
		if err == nil {
			t.Fatal("a non-zero exit code must be an error; reporting success here loses the object from state")
		}
		if !strings.Contains(err.Error(), "Access is denied") {
			t.Errorf("error %q does not carry the directory's stderr", err)
		}
	})

	t.Run("successful removal is nil", func(t *testing.T) {
		if err := CheckDeleteResult(&PSCommandResult{ExitCode: 0}, nil, alreadyGone, "user"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	// An object that is already gone is a successful destroy, not a failure.
	t.Run("already-gone marker is nil", func(t *testing.T) {
		err := CheckDeleteResult(nil, errors.New("... ADIdentityNotFoundException ..."), alreadyGone, "user")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("other transport errors pass through", func(t *testing.T) {
		want := errors.New("winrm: connection refused")

		err := CheckDeleteResult(nil, want, alreadyGone, "user")
		if !errors.Is(err, want) {
			t.Errorf("got %v, want the original error to pass through", err)
		}
	})

	// The marker is per resource type; a GPO's marker must not swallow an AD
	// error and vice versa.
	t.Run("a different marker does not match", func(t *testing.T) {
		err := CheckDeleteResult(nil, errors.New("GpoWithNameNotFound"), alreadyGone, "user")
		if err == nil {
			t.Error("the AD marker must not swallow a GPO error")
		}
	})

	t.Run("the resource type appears in the message", func(t *testing.T) {
		err := CheckDeleteResult(&PSCommandResult{ExitCode: 2, StdErr: "nope"}, nil, "GpoWithNameNotFound", "GPO")
		if err == nil || !strings.Contains(err.Error(), "GPO") {
			t.Errorf("got %v, want the resource type named", err)
		}
	})
}
