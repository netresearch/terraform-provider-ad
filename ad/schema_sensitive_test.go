package ad

import (
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// TestSensitiveAttributes pins the Sensitive flag on every attribute that carries a
// credential. Without it Terraform renders the value in cleartext in plan output,
// which is read in CI logs and pull request comments (GHSA-rj7j-hc27-42gj).
func TestSensitiveAttributes(t *testing.T) {
	p := Provider()

	t.Run("provider", func(t *testing.T) {
		assertSensitive(t, p.Schema, "winrm_password")
	})

	t.Run("ad_user", func(t *testing.T) {
		r, ok := p.ResourcesMap["ad_user"]
		if !ok {
			t.Fatal("resource ad_user is not registered")
		}
		assertSensitive(t, r.Schema, "initial_password")
	})

	// Sensitive sits next to Required and DefaultFunc on winrm_password; this
	// asserts the SDK accepts that combination rather than leaving it to a
	// provider start-up failure.
	t.Run("internal_validate", func(t *testing.T) {
		if err := p.InternalValidate(); err != nil {
			t.Fatalf("provider schema is invalid: %v", err)
		}
	})
}

// TestWriteOnlyPasswordAttribute pins the wiring of initial_password_wo. Each
// assertion guards a way the attribute can silently stop protecting the value:
// without WriteOnly it lands in state, without the version companion no update
// can ever fire, and without the mutual exclusion both passwords could be set.
func TestWriteOnlyPasswordAttribute(t *testing.T) {
	r, ok := Provider().ResourcesMap["ad_user"]
	if !ok {
		t.Fatal("resource ad_user is not registered")
	}

	wo := mustAttr(t, r.Schema, "initial_password_wo")
	version := mustAttr(t, r.Schema, "initial_password_wo_version")
	old := mustAttr(t, r.Schema, "initial_password")

	for _, c := range []schemaCheck{
		{
			"is write-only",
			func() bool { return wo.WriteOnly },
			"initial_password_wo must be WriteOnly, otherwise the password is written to state",
		},
		{
			// Either would mean a value the practitioner never wrote gets applied.
			"is not computed",
			func() bool { return !wo.Computed },
			"initial_password_wo must not be Computed",
		},
		{
			"carries no default",
			func() bool { return wo.Default == nil && wo.DefaultFunc == nil },
			"initial_password_wo must not carry a default",
		},
		{
			"requires its version companion",
			func() bool { return slices.Contains(wo.RequiredWith, "initial_password_wo_version") },
			"initial_password_wo must require initial_password_wo_version; without it no password change can ever be detected",
		},
		{
			"version companion requires it back",
			func() bool { return slices.Contains(version.RequiredWith, "initial_password_wo") },
			"initial_password_wo_version must require initial_password_wo",
		},
		{
			"excludes initial_password",
			func() bool { return slices.Contains(wo.ConflictsWith, "initial_password") },
			"initial_password_wo must conflict with initial_password",
		},
		{
			"is excluded by initial_password",
			func() bool { return slices.Contains(old.ConflictsWith, "initial_password_wo") },
			"initial_password must conflict with initial_password_wo",
		},
		{
			// The version is the only diff the provider can see for a write-only
			// password, so it has to persist.
			"version attribute is visible in state",
			func() bool { return !version.WriteOnly },
			"initial_password_wo_version must not be WriteOnly; it is the change signal and has to persist",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if !c.holds() {
				t.Error(c.msg)
			}
		})
	}

	t.Run("resource schema is valid", func(t *testing.T) {
		if err := r.InternalValidate(nil, true); err != nil {
			t.Fatalf("ad_user schema is invalid: %v", err)
		}
	})
}

// schemaCheck is one named invariant of the schema plus the message explaining
// what breaks when it stops holding.
type schemaCheck struct {
	name  string
	holds func() bool
	msg   string
}

func mustAttr(t *testing.T, s map[string]*schema.Schema, name string) *schema.Schema {
	t.Helper()

	attr, ok := s[name]
	if !ok {
		t.Fatalf("attribute %q does not exist", name)
	}
	return attr
}

func assertSensitive(t *testing.T, s map[string]*schema.Schema, name string) {
	t.Helper()

	attr, ok := s[name]
	if !ok {
		t.Fatalf("attribute %q does not exist", name)
	}
	if !attr.Sensitive {
		t.Errorf("attribute %q holds a credential and must be marked Sensitive", name)
	}
}
