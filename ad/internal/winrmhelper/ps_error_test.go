package winrmhelper

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// A WinRM password that is a substring of an already-gone marker used to break
// every destroy of an object that was already gone: the error text is redacted,
// so matching a marker against it found "ADIdentity<REDACTED>FoundException".
// The destroy then failed, and kept failing on every retry.
//
// These four are not hypothetical passwords chosen to make a point — they are
// the shortest substrings of the markers this package actually matches.
func TestMarkersSurviveRedactionOfTheWinRMPassword(t *testing.T) {
	cases := []struct {
		password string
		stderr   string
		marker   string
	}{
		{"Not", "ADIdentityNotFoundException", "ADIdentityNotFoundException"},
		{"Data", "InvalidData", "InvalidData"},
		{"Item", "ItemNotFoundException", "ItemNotFoundException"},
		{"Link", "GpoLinkNotFound", "GpoLinkNotFound"},
		{"NotFound", "GpoWithNameNotFound", "GpoWithNameNotFound"},
	}

	for _, c := range cases {
		t.Run(c.password, func(t *testing.T) {
			err := checkPSResult(&PSCommandResult{ExitCode: 1, StdErr: c.stderr}, nil,
				"removing the object", c.password)
			if err == nil {
				t.Fatal("a non-zero exit code must produce an error")
			}

			// The guard that gives this test its teeth: the rendered text really
			// is damaged. Without that, the assertion below would hold for the
			// wrong reason and a return to matching on err.Error() would pass.
			if strings.Contains(err.Error(), c.marker) {
				t.Fatalf("fixture does not exercise the defect: %q survives redaction in %q",
					c.marker, err.Error())
			}

			if !ErrorMentions(err, c.marker) {
				t.Errorf("ErrorMentions did not find %q; rendered error was %q", c.marker, err.Error())
			}
			if CheckDeleteResult(err, c.marker) != nil {
				t.Errorf("an object that is already gone must be a successful destroy")
			}
		})
	}
}

func TestErrorMentionsReadsTheRawStreams(t *testing.T) {
	err := checkPSResult(&PSCommandResult{ExitCode: 1, StdErr: "on stderr", Stdout: "on stdout"}, nil,
		"doing the thing", "")

	for _, marker := range []string{"on stderr", "on stdout"} {
		if !ErrorMentions(err, marker) {
			t.Errorf("%q not found", marker)
		}
	}
	if ErrorMentions(err, "not present anywhere") {
		t.Error("matched a marker that is in neither stream")
	}
	if ErrorMentions(err, "") {
		t.Error("an empty marker matches every string and must never count as a match")
	}
	if ErrorMentions(nil, "anything") {
		t.Error("a nil error mentions nothing")
	}
}

// A transport failure carries no exit code, and the marker can only be in the
// transport error itself.
func TestErrorMentionsCoversTheTransportFailure(t *testing.T) {
	err := checkPSResult(nil, errors.New("winrm: ADIdentityNotFoundException"), "removing the user", "")

	if !ErrorMentions(err, "ADIdentityNotFoundException") {
		t.Errorf("marker not found in the transport error: %q", err.Error())
	}
	if CheckDeleteResult(err, "ADIdentityNotFoundException") != nil {
		t.Error("an already-gone object reported as a transport error is still a successful destroy")
	}
}

// An error that did not come from a command has nothing but its text, so that is
// what gets matched — GetGPLinkFromHost's "did not find" is such a case.
func TestErrorMentionsFallsBackToTheTextForAPlainError(t *testing.T) {
	if !ErrorMentions(errors.New(`did not find a container with DN "x"`), "did not find") {
		t.Error("a plain error must still be matchable")
	}
}

// errors.As has to reach the command error through a caller's wrapping, or the
// marker check silently falls back to the redacted text.
func TestErrorMentionsReachesThroughWrapping(t *testing.T) {
	inner := checkPSResult(&PSCommandResult{ExitCode: 1, StdErr: "ADIdentityNotFoundException"}, nil,
		"removing the user", "Not")
	wrapped := fmt.Errorf("while doing something larger: %w", inner)

	if !ErrorMentions(wrapped, "ADIdentityNotFoundException") {
		t.Errorf("marker lost through %%w wrapping: %q", wrapped.Error())
	}
}

func TestPSErrorRendersRedacted(t *testing.T) {
	const password = "sup3rs3cr3t"
	err := checkPSResult(&PSCommandResult{
		ExitCode: 1,
		StdErr:   "failed for " + password,
		Stdout:   "also " + password,
	}, nil, "creating the user", password)

	if strings.Contains(err.Error(), password) {
		t.Fatalf("password leaked into the rendered error: %q", err.Error())
	}
	if strings.Count(err.Error(), "<REDACTED>") != 2 {
		t.Errorf("expected both streams redacted, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "while creating the user") {
		t.Errorf("the rendered error must still name what was attempted: %q", err.Error())
	}
}

// The transport branch renders too, and it renders redacted.
func TestPSErrorRendersATransportFailureRedacted(t *testing.T) {
	const password = "sup3rs3cr3t"
	err := checkPSResult(&PSCommandResult{ExitCode: 1, StdErr: "x"},
		fmt.Errorf("http error 500: body mentioning %s", password), "creating the user", password)

	if strings.Contains(err.Error(), password) {
		t.Fatalf("password leaked through the transport error: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "while creating the user") {
		t.Errorf("unexpected message: %q", err.Error())
	}
}
