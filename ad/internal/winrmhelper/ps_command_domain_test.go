package winrmhelper

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"
)

// Domain() turns on the Invoke-Command branch whenever credentials are passed,
// and that branch was asserted by nothing: deleting the ConvertTo-Json append
// inside the script block, swapping -Computername for -Server, or dropping
// -Authentication Kerberos all left the suite green. Domain() reaches fifteen
// call sites — every Group Policy operation in the provider — and three of them
// unmarshal the JSON this branch produces.
func domainConf(t *testing.T, realm string) *config.ProviderConf {
	t.Helper()
	conf := config.NewProviderConf(&config.Settings{
		WinRMUsername:        "svc-terraform",
		WinRMPassword:        "hunter2",
		WinRMProto:           "https",
		WinRMPassCredentials: true,
		DomainController:     "dc01.example.com",
		DomainName:           "example.com",
		KrbRealm:             realm,
	})
	if !conf.IsPassCredentialsEnabled() {
		t.Fatal("fixture does not pass credentials, so the Invoke-Command branch is off and every assertion below is vacuous")
	}
	return conf
}

func TestDomainRunsThroughInvokeCommand(t *testing.T) {
	got := command(domainConf(t, "OTHER.REALM"), Domain())

	if !strings.Contains(got, "Invoke-Command -Authentication Kerberos") {
		t.Errorf("Kerberos authentication is not requested: %s", got)
	}
	if !strings.Contains(got, "-ScriptBlock {Get-ADUser -Identity x") {
		t.Errorf("the command is not inside the script block: %s", got)
	}
	// The remote host is named with -Computername here; -Server is what a
	// command addressed at a domain controller uses, and it is not valid for
	// Invoke-Command.
	if !strings.Contains(got, "-Computername example.com") {
		t.Errorf("the domain is not passed as -Computername: %s", got)
	}
	if strings.Contains(got, "-Server ") {
		t.Errorf("-Server must not be used on the Invoke-Command branch: %s", got)
	}
}

// The JSON conversion has to happen INSIDE the script block. Outside it, the
// caller receives the rendering of a deserialised remote object rather than the
// JSON document it unmarshals, and GetGPOFromHost, NewGPO and NewGPLink fail at
// runtime.
func TestDomainWithJSONConvertsInsideTheScriptBlock(t *testing.T) {
	got := command(domainConf(t, "OTHER.REALM"), Domain(), JSONOutput())

	block := strings.Index(got, "-ScriptBlock {")
	convert := strings.Index(got, "| ConvertTo-Json")
	closing := strings.Index(got, "}")

	if block < 0 || convert < 0 {
		t.Fatalf("script block or conversion missing: %s", got)
	}
	if !(block < convert && convert < closing) {
		t.Errorf("ConvertTo-Json is not inside the script block: %s", got)
	}
	if strings.Count(got, "ConvertTo-Json") != 1 {
		t.Errorf("the conversion must be appended exactly once: %s", got)
	}
}

// When the Kerberos realm equals the domain, addressing the domain by name
// resolves to the realm and the command fails; the local machine is used
// instead.
func TestDomainFallsBackToTheLocalMachineWhenTheRealmMatches(t *testing.T) {
	got := command(domainConf(t, "example.com"), Domain())

	if !strings.Contains(got, "-Computername $env:computername") {
		t.Errorf("expected the local machine, got: %s", got)
	}
}

// Without credentials there is no Invoke-Command, and the domain is addressed
// the ordinary way. This is the branch every call site takes when the provider
// is configured without credential passing.
func TestDomainWithoutCredentialsDoesNotInvoke(t *testing.T) {
	conf := config.NewProviderConf(&config.Settings{
		DomainName:       "example.com",
		DomainController: "dc01.example.com",
	})
	if conf.IsPassCredentialsEnabled() {
		t.Fatal("fixture passes credentials; this test asserts the other branch")
	}

	got := command(conf, Domain(), JSONOutput())

	if strings.Contains(got, "Invoke-Command") {
		t.Errorf("Invoke-Command must follow credential passing: %s", got)
	}
	if !strings.HasSuffix(got, "| ConvertTo-Json") {
		t.Errorf("the conversion is appended at the end here: %s", got)
	}
}
