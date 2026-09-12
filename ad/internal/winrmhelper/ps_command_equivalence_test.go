package winrmhelper

import (
	"testing"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"
)

// The refactor moved 49 call sites from hand-built option structs to options,
// and the only thing standing between it and a silently dropped field was a
// human reading the diff. This is that check, mechanised: for every option
// combination the package uses, the rendered command must equal what the old
// literal produced.
//
// The literals on the right are transcribed from the pre-refactor call sites.
// They are the point of the test: if an option stops setting a field, the two
// sides diverge here rather than at a domain controller.
func TestOptionsRenderWhatTheOldLiteralsDid(t *testing.T) {
	settings := &config.Settings{
		WinRMUsername:        "svc-terraform",
		WinRMPassword:        "hunter2",
		WinRMProto:           "https",
		WinRMPassCredentials: true,
		DomainController:     "dc01.example.com",
		DomainName:           "example.com",
		KrbRealm:             "OTHER.REALM",
	}
	conf := config.NewProviderConf(settings)
	if !conf.IsPassCredentialsEnabled() || conf.IdentifyDomainController() == "" {
		t.Fatal("fixture resolves neither credentials nor a controller; every comparison below would be zero against zero")
	}

	// What every old call site started from, before it assigned anything.
	base := func() CreatePSCommandOpts {
		return CreatePSCommandOpts{
			ExecLocally:     conf.IsConnectionTypeLocal(),
			PassCredentials: conf.IsPassCredentialsEnabled(),
			Username:        settings.WinRMUsername,
			Password:        settings.WinRMPassword,
			Server:          conf.IdentifyDomainController(),
		}
	}
	// What NewDomainPSCommandOpts did on top of it.
	domainBase := func() CreatePSCommandOpts {
		o := base()
		o.InvokeCommand = conf.IsPassCredentialsEnabled()
		o.Server = settings.DomainName
		return o
	}

	cases := []struct {
		name    string
		options []PSOption
		old     CreatePSCommandOpts
	}{
		{"plain", nil, base()},
		{"JSONOutput", []PSOption{JSONOutput()}, func() CreatePSCommandOpts {
			o := base()
			o.JSONOutput = true
			return o
		}()},
		{"JSONOutput+ForceArray", []PSOption{JSONOutput(), ForceArray()}, func() CreatePSCommandOpts {
			o := base()
			o.JSONOutput = true
			o.ForceArray = true
			return o
		}()},
		{"Domain", []PSOption{Domain()}, domainBase()},
		{"Domain+JSONOutput", []PSOption{Domain(), JSONOutput()}, func() CreatePSCommandOpts {
			o := domainBase()
			o.JSONOutput = true
			return o
		}()},
		{"ComposedCommand", []PSOption{ComposedCommand()}, func() CreatePSCommandOpts {
			o := base()
			o.Server = ""
			o.SkipCredSuffix = true
			return o
		}()},
		{"SkipCredentialPreamble", []PSOption{SkipCredentialPreamble()}, func() CreatePSCommandOpts {
			o := base()
			o.SkipCredPrefix = true
			return o
		}()},
		// UploadFiletoSYSVOL's literal also set SkipCredPrefix and SkipCredSuffix.
		// Both are dead with PassCredentials false — this is what says so.
		{"WithoutCredentials", []PSOption{WithoutCredentials()}, CreatePSCommandOpts{
			ExecLocally:     conf.IsConnectionTypeLocal(),
			PassCredentials: false,
			SkipCredPrefix:  true,
			SkipCredSuffix:  true,
		}},
	}

	const cmd = "Get-ADUser -Identity x"
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := NewPSCommand([]string{cmd}, c.old).String()
			got := NewPSCommand([]string{cmd}, NewPSCommandOpts(conf, c.options...)).String()

			if got != want {
				t.Errorf("rendered command differs from the pre-refactor one\n old: %s\n new: %s", want, got)
			}
		})
	}
}

func TestBracketLoneObject(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"a":1}`, `[{"a":1}]`},
		{`[{"a":1}]`, `[{"a":1}]`},
		{"", ""},
	}
	for _, c := range cases {
		if got := bracketLoneObject(c.in); got != c.want {
			t.Errorf("bracketLoneObject(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
