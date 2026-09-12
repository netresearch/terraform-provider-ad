package winrmhelper

import (
	"errors"
	"fmt"
	"testing"
)

// TestCheckDeleteResult covers the case the delete paths used to get wrong: the
// directory refuses the removal, PSCommand.Run reports no error, and only the
// exit code says so. Treating that as success let Terraform drop a resource from
// state while the object was still in the directory. RunPSCommand turns that
// exit code into an error, and this decides which errors are still a success.
func TestCheckDeleteResult(t *testing.T) {
	const alreadyGone = "ADIdentityNotFoundException"

	t.Run("a refused removal stays an error", func(t *testing.T) {
		err := CheckDeleteResult(errors.New("while removing the user: exit code 1, stderr: Access is denied"), alreadyGone)
		if err == nil {
			t.Fatal("a refused removal must be an error; reporting success here loses the object from state")
		}
	})

	t.Run("a successful removal is nil", func(t *testing.T) {
		if err := CheckDeleteResult(nil, alreadyGone); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	// An object that is already gone is a successful destroy, not a failure.
	// It reaches us either as a transport error or as stderr behind a non-zero
	// exit code, and both arrive here inside the error text.
	t.Run("already-gone marker is nil", func(t *testing.T) {
		for _, err := range []error{
			errors.New("... ADIdentityNotFoundException ..."),
			fmt.Errorf("while removing the user: exit code 1, stderr: %s, stdout: ", alreadyGone),
		} {
			if got := CheckDeleteResult(err, alreadyGone); got != nil {
				t.Errorf("unexpected error for %q: %v", err, got)
			}
		}
	})

	t.Run("other transport errors pass through", func(t *testing.T) {
		want := errors.New("winrm: connection refused")

		if err := CheckDeleteResult(want, alreadyGone); !errors.Is(err, want) {
			t.Errorf("got %v, want the original error to pass through", err)
		}
	})

	// The marker is per resource type; a GPO's marker must not swallow an AD
	// error and vice versa.
	t.Run("a different marker does not match", func(t *testing.T) {
		if err := CheckDeleteResult(errors.New("GpoWithNameNotFound"), alreadyGone); err == nil {
			t.Error("the AD marker must not swallow a GPO error")
		}
	})

	// RemoveGPLink tolerates three different texts for the same condition.
	t.Run("any of several markers matches", func(t *testing.T) {
		markers := []string{"GpoLinkNotFound", "GpoWithIdNotFound", "There is no such object on the server"}
		for _, m := range markers {
			if err := CheckDeleteResult(fmt.Errorf("while removing the GPO link: exit code 1, stderr: %s", m), markers...); err != nil {
				t.Errorf("marker %q not recognised: %v", m, err)
			}
		}
		if err := CheckDeleteResult(errors.New("Access is denied"), markers...); err == nil {
			t.Error("an unrelated failure must not be swallowed")
		}
	})

	t.Run("no markers at all passes every error through", func(t *testing.T) {
		if err := CheckDeleteResult(errors.New("boom")); err == nil {
			t.Error("expected the error to pass through")
		}
	})
}
