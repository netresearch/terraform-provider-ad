package winrmhelper

import (
	"fmt"
	"strings"
	"testing"
)

func TestCheckPSResultPassesASuccessfulCommandThrough(t *testing.T) {
	if err := checkPSResult(&PSCommandResult{Stdout: "ok"}, nil, "creating the group", ""); err != nil {
		t.Fatalf("expected no error for exit code 0, got %v", err)
	}
}

func TestCheckPSResultReportsATransportFailure(t *testing.T) {
	err := checkPSResult(nil, fmt.Errorf("connection refused"), "creating the group", "")
	if err == nil {
		t.Fatal("expected an error when Run failed")
	}
	if got := err.Error(); got != "while creating the group: connection refused" {
		t.Errorf("unexpected message: %q", got)
	}
}

// A command the directory refuses returns no error and a non-zero exit code.
// Missing that is the defect the helper exists to prevent: Terraform would take
// a destroy that did not happen for a success.
func TestCheckPSResultReportsANonZeroExitCode(t *testing.T) {
	err := checkPSResult(&PSCommandResult{
		ExitCode: 1,
		StdErr:   "GpoWithNameAlreadyExists",
		Stdout:   "partial output",
	}, nil, "creating the GPO", "")
	if err == nil {
		t.Fatal("expected an error for a non-zero exit code")
	}
	for _, want := range []string{"while creating the GPO", "exit code 1", "GpoWithNameAlreadyExists", "partial output"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q does not contain %q", err.Error(), want)
		}
	}
}

// The error reaches the Terraform console and CI logs, and a failing PowerShell
// error record quotes the command that produced it — which for New-ADUser is a
// command carrying the account password.
func TestCheckPSResultRedactsPasswordsInBothStreams(t *testing.T) {
	const winrmPassword = "winrm-s3cr3t"
	const accountPassword = "account-s3cr3t"

	err := checkPSResult(&PSCommandResult{
		ExitCode: 1,
		StdErr:   fmt.Sprintf(`New-ADUser -AccountPassword (ConvertTo-SecureString -AsPlainText "%s" -Force) failed`, accountPassword),
		Stdout:   fmt.Sprintf("WinRM password was %s", winrmPassword),
	}, nil, "creating the user", winrmPassword)

	// Two distinct values on purpose. With one value the literal replacement of
	// the WinRM password alone satisfies both assertions, and the four
	// -AccountPassword patterns are never exercised — they could all be deleted
	// with the suite still green.
	for _, secret := range []string{winrmPassword, accountPassword} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("%q leaked into the error: %q", secret, err.Error())
		}
	}
	if strings.Count(err.Error(), "<REDACTED>") != 2 {
		t.Errorf("expected both streams redacted, got %q", err.Error())
	}
}

// The -AccountPassword patterns have to work on their own: a run without passed
// credentials has no WinRM password, so the literal replacement does nothing.
func TestCheckPSResultRedactsTheAccountPasswordWithoutAWinRMPassword(t *testing.T) {
	const accountPassword = "account-s3cr3t"

	err := checkPSResult(&PSCommandResult{
		ExitCode: 1,
		StdErr:   fmt.Sprintf(`New-ADUser -AccountPassword (ConvertTo-SecureString -AsPlainText "%s" -Force) failed`, accountPassword),
	}, nil, "creating the user", "")

	if strings.Contains(err.Error(), accountPassword) {
		t.Errorf("account password leaked with no WinRM password set: %q", err.Error())
	}
}
