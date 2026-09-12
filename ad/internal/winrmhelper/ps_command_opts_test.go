package winrmhelper

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"
)

// Every value here is deliberately non-zero. A fixture that leaves a field at
// its zero value cannot tell a constructor that sets it from one that does not:
// the assertion compares false against false and holds either way. Three of the
// five assertions in the first version of this test were vacuous exactly that
// way, and a mutation removing the field from the constructor survived.
func connectedSettings() *config.Settings {
	return &config.Settings{
		WinRMUsername:        "svc-terraform",
		WinRMPassword:        "hunter2",
		WinRMProto:           "https", // with the switch below, enables credential passing
		WinRMPassCredentials: true,
		DomainController:     "dc01.example.com",
		DomainName:           "example.com",
	}
}

func TestNewPSCommandOptsFillsTheConnectionFields(t *testing.T) {
	conf := config.NewProviderConf(connectedSettings())

	// Guard the fixture itself: if either of these is false, the assertions
	// below compare a zero value against a zero value and prove nothing.
	if !conf.IsPassCredentialsEnabled() {
		t.Fatal("fixture does not enable credential passing")
	}
	if conf.IdentifyDomainController() == "" {
		t.Fatal("fixture does not resolve a domain controller")
	}

	opts := NewPSCommandOpts(conf)

	if opts.Username != "svc-terraform" {
		t.Errorf("Username = %q, want the configured user", opts.Username)
	}
	if opts.Password != "hunter2" {
		t.Errorf("Password = %q, want the configured password", opts.Password)
	}
	if !opts.PassCredentials {
		t.Error("PassCredentials must follow the provider setting, which this fixture enables")
	}
	if opts.Server != "dc01.example.com" {
		t.Errorf("Server = %q, want the configured domain controller", opts.Server)
	}

	// Everything a call site is expected to set itself must start off zero, or
	// a site that does not mention a switch silently inherits one.
	if opts.JSONOutput || opts.ForceArray || opts.InvokeCommand ||
		opts.SkipCredPrefix || opts.SkipCredSuffix {
		t.Errorf("a caller-controlled switch defaults to true: %+v", opts)
	}
}

// TestNewPSCommandOptsExecLocally is separate and deliberately weaker, and says
// so rather than pretending otherwise.
//
// IsConnectionTypeLocal returns true only on Windows, and only when host, user
// and password are all empty. On every other platform it is false, which is also
// the zero value — so off Windows no assertion here can distinguish a
// constructor that sets ExecLocally from one that omits it. The guard against
// omission is the field-by-field comparison done during the refactor, not this
// test.
func TestNewPSCommandOptsExecLocally(t *testing.T) {
	local := config.NewProviderConf(&config.Settings{}) // no host, no credentials

	if got := NewPSCommandOpts(local).ExecLocally; got != local.IsConnectionTypeLocal() {
		t.Errorf("ExecLocally = %v, want %v", got, local.IsConnectionTypeLocal())
	}
	if runtime.GOOS != "windows" {
		t.Skip("IsConnectionTypeLocal is false on every non-Windows platform; this case cannot fail here")
	}
	if !NewPSCommandOpts(local).ExecLocally {
		t.Error("ExecLocally must be true on Windows with no host and no credentials")
	}
}

// TestNewDomainPSCommandOptsTargetsTheDomain pins the second constructor. It
// differs from the first in exactly two fields, and both matter: aiming Server
// at the domain rather than a controller is what the Group Policy cmdlets need,
// and InvokeCommand has to follow the credential setting or a passed-credential
// run reaches the wrong shell.
func TestNewDomainPSCommandOptsTargetsTheDomain(t *testing.T) {
	t.Run("ordinary domain", func(t *testing.T) {
		conf := config.NewProviderConf(&config.Settings{
			DomainName: "example.com",
			KrbRealm:   "OTHER.REALM",
		})

		if got := NewDomainPSCommandOpts(conf).Server; got != "example.com" {
			t.Errorf("Server = %q, want the domain name", got)
		}
	})

	// InvokeCommand has to be asserted with credential passing actually ON.
	// With the default settings IsPassCredentialsEnabled() is false, which is
	// also the zero value of the field — so comparing the two passes whether
	// the constructor sets it or not, and a mutation that drops the assignment
	// survives. Passing credentials needs https AND the switch.
	t.Run("InvokeCommand follows credential passing", func(t *testing.T) {
		on := config.NewProviderConf(&config.Settings{
			DomainName:           "example.com",
			WinRMProto:           "https",
			WinRMPassCredentials: true,
		})
		if !on.IsPassCredentialsEnabled() {
			t.Fatal("test setup does not enable credential passing")
		}
		if !NewDomainPSCommandOpts(on).InvokeCommand {
			t.Error("InvokeCommand must be true when credentials are passed")
		}

		off := config.NewProviderConf(&config.Settings{DomainName: "example.com"})
		if NewDomainPSCommandOpts(off).InvokeCommand {
			t.Error("InvokeCommand must be false when credentials are not passed")
		}
	})

	// When the realm equals the domain, the commands have to run against the
	// local machine instead, or they resolve to the Kerberos realm and fail.
	t.Run("realm equals the domain", func(t *testing.T) {
		conf := config.NewProviderConf(&config.Settings{
			DomainName: "example.com",
			KrbRealm:   "example.com",
		})

		if got := NewDomainPSCommandOpts(conf).Server; got != "$env:computername" {
			t.Errorf("Server = %q, want $env:computername", got)
		}
	})

	// Everything else must still come from the base constructor.
	t.Run("keeps the connection fields", func(t *testing.T) {
		conf := config.NewProviderConf(&config.Settings{
			WinRMUsername: "svc-terraform",
			WinRMPassword: "hunter2",
			DomainName:    "example.com",
		})

		opts := NewDomainPSCommandOpts(conf)

		if opts.Username != "svc-terraform" || opts.Password != "hunter2" {
			t.Errorf("credentials lost: %+v", opts)
		}
		if opts.JSONOutput || opts.ForceArray || opts.SkipCredPrefix || opts.SkipCredSuffix {
			t.Errorf("a caller-controlled switch defaults to true: %+v", opts)
		}
	})
}

// literalOpts matches a CreatePSCommandOpts literal assigned to a variable —
// the shape NewPSCommandOpts replaces.
var literalOpts = regexp.MustCompile(`\w+\s*:?=\s*CreatePSCommandOpts\{`)

// TestNoHandBuiltPSCommandOpts keeps the boilerplate from growing back.
//
// Those five connection fields were repeated verbatim at forty-nine call sites.
// Beyond the duplication, a site that builds the options by hand can silently
// miss a field — and the one that matters most is Password, where the zero
// value is a working struct that authenticates as nobody.
//
// Three inline literals in winrm_helper.go are deliberately exempt: they pass
// the options straight into NewPSCommand and set PassCredentials false with the
// credential prefix and suffix skipped, which the constructor does not fit.
func TestNoHandBuiltPSCommandOpts(t *testing.T) {
	const exempt = "winrm_helper.go"

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}

	checked, found := 0, 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") || name == exempt {
			continue
		}
		checked++

		body, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}

		for i, line := range strings.Split(string(body), "\n") {
			if literalOpts.MatchString(line) {
				found++
				t.Errorf("%s:%d builds CreatePSCommandOpts by hand:\n\t%s\n"+
					"Use NewPSCommandOpts(conf) and assign only what differs.",
					name, i+1, strings.TrimSpace(line))
			}
		}
	}

	if checked == 0 {
		t.Fatal("no source files were inspected")
	}
	t.Logf("inspected %d source files, %d hand-built literals", checked, found)
}
