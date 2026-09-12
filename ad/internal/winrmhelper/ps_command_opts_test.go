package winrmhelper

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"
)

func TestNewPSCommandOptsFillsTheConnectionFields(t *testing.T) {
	conf := config.NewProviderConf(&config.Settings{
		WinRMUsername: "svc-terraform",
		WinRMPassword: "hunter2",
	})

	opts := NewPSCommandOpts(conf)

	if opts.Username != "svc-terraform" {
		t.Errorf("Username = %q, want the configured user", opts.Username)
	}
	if opts.Password != "hunter2" {
		t.Errorf("Password = %q, want the configured password", opts.Password)
	}
	if opts.ExecLocally != conf.IsConnectionTypeLocal() {
		t.Error("ExecLocally does not follow the connection type")
	}
	if opts.PassCredentials != conf.IsPassCredentialsEnabled() {
		t.Error("PassCredentials does not follow the provider setting")
	}
	if opts.Server != conf.IdentifyDomainController() {
		t.Errorf("Server = %q, want the identified domain controller", opts.Server)
	}

	// Everything a call site is expected to set itself must start off zero, or
	// a site that does not mention a switch silently inherits one.
	if opts.JSONOutput || opts.ForceArray || opts.InvokeCommand ||
		opts.SkipCredPrefix || opts.SkipCredSuffix {
		t.Errorf("a caller-controlled switch defaults to true: %+v", opts)
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
