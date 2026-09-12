package winrmhelper

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"
)

// The options are asserted through the command they produce, not through the
// fields they set. The field is an implementation detail; the command line is
// what reaches the domain controller, and for ComposedCommand it is the only
// place the two switches can be seen to belong together.
func command(conf *config.ProviderConf, opts ...PSOption) string {
	return NewPSCommand([]string{"Get-ADUser -Identity x"}, NewPSCommandOpts(conf, opts...)).String()
}

func credentialConf(t *testing.T) *config.ProviderConf {
	t.Helper()
	conf := config.NewProviderConf(&config.Settings{
		WinRMUsername:        "svc-terraform",
		WinRMPassword:        "hunter2",
		WinRMProto:           "https",
		WinRMPassCredentials: true,
		DomainController:     "dc01.example.com",
		DomainName:           "example.com",
	})
	if !conf.IsPassCredentialsEnabled() {
		t.Fatal("fixture does not enable credential passing; every assertion below would be vacuous")
	}
	return conf
}

func TestJSONOutputPipesThroughConvertToJson(t *testing.T) {
	conf := credentialConf(t)

	if got := command(conf); strings.Contains(got, "ConvertTo-Json") {
		t.Errorf("plain command must not convert to JSON: %s", got)
	}
	if got := command(conf, JSONOutput()); !strings.Contains(got, "| ConvertTo-Json") {
		t.Errorf("JSONOutput must pipe through ConvertTo-Json: %s", got)
	}
}

// ComposedCommand is for a command assembled from sub-commands that carry their
// own credentials. The preamble still has to be emitted once; the suffix and the
// server must not be appended, or they attach to the last cmdlet of the pipeline
// instead of to the whole.
func TestComposedCommandKeepsThePreambleAndDropsTheSuffix(t *testing.T) {
	conf := credentialConf(t)

	plain := command(conf)
	if !strings.Contains(plain, "-Credential $Credential") || !strings.Contains(plain, "-Server dc01.example.com") {
		t.Fatalf("fixture does not produce the suffix this option removes: %s", plain)
	}

	got := command(conf, ComposedCommand())
	if !strings.Contains(got, "$Credential = New-Object") {
		t.Errorf("the credential preamble must survive: %s", got)
	}
	if strings.Contains(got, "-Credential $Credential") {
		t.Errorf("the -Credential suffix must not be appended: %s", got)
	}
	if strings.Contains(got, "-Server ") {
		t.Errorf("no server may be appended: %s", got)
	}
}

func TestWithoutCredentialsAddsNothingToTheCommand(t *testing.T) {
	conf := credentialConf(t)

	got := command(conf, WithoutCredentials())
	for _, unwanted := range []string{"$Credential", "-Credential", "-Server ", "hunter2"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("WithoutCredentials must not emit %q: %s", unwanted, got)
		}
	}
	if !strings.Contains(got, "Get-ADUser -Identity x") {
		t.Errorf("the command itself is gone: %s", got)
	}
}

// SkipCredentialPreamble is the other half of ComposedCommand: the sub-commands
// keep their own -Credential and -Server, and leave out the preamble that the
// wrapper emits once.
func TestSkipCredentialPreambleKeepsTheSuffix(t *testing.T) {
	conf := credentialConf(t)

	got := command(conf, SkipCredentialPreamble())
	if strings.Contains(got, "$Credential = New-Object") {
		t.Errorf("the preamble must be left to the wrapping command: %s", got)
	}
	if !strings.Contains(got, "-Credential $Credential") {
		t.Errorf("the sub-command still needs the -Credential suffix: %s", got)
	}
}

func TestForceArrayWrapsASingleObject(t *testing.T) {
	opts := CreatePSCommandOpts{ForceArray: true}
	if !opts.ForceArray {
		t.Fatal("fixture is wrong")
	}
	conf := credentialConf(t)
	if !NewPSCommandOpts(conf, ForceArray()).ForceArray {
		t.Error("ForceArray must set the switch that brackets a lone JSON object")
	}
}
