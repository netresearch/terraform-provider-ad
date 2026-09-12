package winrmhelper

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// The case that motivated Secret(): a password containing a double quote is not
// matched by any of the -AccountPassword patterns, so before this the full
// password reached the Terraform console on every failed New-ADUser.
//
// The rendering below is the real one — SanitiseString turns `"` into “ `" “
// and %q then escapes that quote again — so the fixture fails the same way the
// provider did rather than a way invented for the test.
func TestSecretRedactsAPasswordThePatternsCannotMatch(t *testing.T) {
	const raw = `pa"ssWord1!`
	rendered := strconv.Quote(SanitiseString(raw))
	command := fmt.Sprintf(
		`New-ADUser -Passthru -Name "u" -AccountPassword (ConvertTo-SecureString -AsPlainText %s -Force)`,
		rendered)

	// Guard: without this the test could pass because the patterns happened to
	// work, and it would prove nothing about Secret(). The needle is the text as
	// it stands in the command — the escaped rendering — because that is what
	// leaks and what the password is trivially recovered from.
	if !strings.Contains(redactSensitiveData(command, ""), rendered) {
		t.Fatal("fixture does not reproduce the pattern bypass; the password is already redacted without SecretPassword()")
	}

	got := redactSensitiveData(command, "", rendered)
	if strings.Contains(got, rendered) || strings.Contains(got, "ssWord1!") {
		t.Errorf("password survived redaction: %s", got)
	}
	if !strings.Contains(got, "<REDACTED>") {
		t.Errorf("nothing was redacted: %s", got)
	}
}

// A password the patterns do handle must still be redacted exactly once, not
// mangled by the two mechanisms overlapping.
func TestSecretAndThePatternsAgreeOnAnOrdinaryPassword(t *testing.T) {
	const raw = "Sup3rS3cret!"
	rendered := strconv.Quote(SanitiseString(raw))
	command := fmt.Sprintf(
		`New-ADUser -AccountPassword (ConvertTo-SecureString -AsPlainText %s -Force)`, rendered)

	got := redactSensitiveData(command, "", rendered)
	if strings.Contains(got, raw) {
		t.Errorf("password survived: %s", got)
	}
}

// The registered secret has to reach the rendered error, which is the surface
// the console and CI logs see.
func TestSecretReachesTheRenderedError(t *testing.T) {
	const raw = `pa"ssWord1!`
	rendered := strconv.Quote(SanitiseString(raw))

	err := checkPSResult(&PSCommandResult{
		ExitCode: 1,
		StdErr:   "New-ADUser failed at -AsPlainText " + rendered,
	}, nil, "creating the user", "", rendered)

	if strings.Contains(err.Error(), "ssWord1!") {
		t.Errorf("password leaked into the error: %q", err.Error())
	}
}

// The wiring, not the unit: a secret has to travel from the option through the
// options struct to the command, or every assertion above passes while nothing
// registered at a real call site is ever redacted.
func TestSecretIsCarriedByTheOptions(t *testing.T) {
	conf := credentialConf(t)
	opts := NewPSCommandOpts(conf, SecretPassword(`rendered-secret`))

	if len(opts.Secrets) != 1 || opts.Secrets[0] != strconv.Quote("rendered-secret") {
		t.Fatalf("Secret did not reach the options: %#v", opts.Secrets)
	}

	// And from there into what a failure renders.
	err := checkPSResult(&PSCommandResult{ExitCode: 1, StdErr: `failed at "rendered-secret"`},
		nil, "creating the user", opts.Password, opts.Secrets...)
	if strings.Contains(err.Error(), "rendered-secret") {
		t.Errorf("the registered secret was not redacted: %q", err.Error())
	}
}

func TestSecretIgnoresAnEmptyValue(t *testing.T) {
	// An empty secret would replace at every position and redact the whole text.
	if got := redactSensitiveData("nothing secret here", "", ""); got != "nothing secret here" {
		t.Errorf("an empty secret must be ignored, got %q", got)
	}

	opts := CreatePSCommandOpts{}
	SecretPassword("")(nil, &opts)
	if len(opts.Secrets) != 0 {
		t.Errorf("an absent password must not register a secret: %v", opts.Secrets)
	}
}

// strconv.Quote("") is the two-character string `""`, not empty. Registering it
// would redact every empty string literal the provider renders — an attribute set
// to "", a JSON field, the lot. SecretPassword takes the password rather than the
// rendering so that this exception lives in one place instead of at each call
// site, where it was wrong at both.
func TestAnAbsentPasswordRegistersNothing(t *testing.T) {
	if strconv.Quote("") == "" {
		t.Fatal(`strconv.Quote("") is empty here, so this test cannot exercise the case it exists for`)
	}

	opts := CreatePSCommandOpts{}
	SecretPassword("")(nil, &opts)
	if len(opts.Secrets) != 0 {
		t.Fatalf("an absent password must register no secret, got %q", opts.Secrets)
	}

	command := `New-ADUser -Name "bob" -OtherAttributes @{'nick'=""}`
	if got := redactSensitiveData(command, "", opts.Secrets...); got != command {
		t.Errorf("an unrelated command was rewritten: %s", got)
	}
}

func TestSecretPasswordRegistersTheRendering(t *testing.T) {
	opts := CreatePSCommandOpts{}
	SecretPassword(`pa"ssWord1!`)(nil, &opts)

	if len(opts.Secrets) != 1 || opts.Secrets[0] != strconv.Quote(`pa"ssWord1!`) {
		t.Fatalf("expected the quoted rendering, got %q", opts.Secrets)
	}
}
