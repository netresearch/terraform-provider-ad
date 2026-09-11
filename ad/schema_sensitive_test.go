package ad

import (
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

	wo, ok := r.Schema["initial_password_wo"]
	if !ok {
		t.Fatal("attribute initial_password_wo does not exist")
	}
	version, ok := r.Schema["initial_password_wo_version"]
	if !ok {
		t.Fatal("attribute initial_password_wo_version does not exist")
	}
	old, ok := r.Schema["initial_password"]
	if !ok {
		t.Fatal("attribute initial_password does not exist")
	}

	t.Run("is write-only", func(t *testing.T) {
		if !wo.WriteOnly {
			t.Error("initial_password_wo must be WriteOnly, otherwise the password is written to state")
		}
	})

	// A WriteOnly attribute must never be Computed and must never carry a default:
	// the SDK rejects both, and either would mean a value the practitioner did not
	// write ends up being applied.
	t.Run("carries no computed value or default", func(t *testing.T) {
		if wo.Computed {
			t.Error("initial_password_wo must not be Computed")
		}
		if wo.Default != nil || wo.DefaultFunc != nil {
			t.Error("initial_password_wo must not carry a default")
		}
	})

	t.Run("requires its version companion", func(t *testing.T) {
		if !contains(wo.RequiredWith, "initial_password_wo_version") {
			t.Error("initial_password_wo must require initial_password_wo_version; without it no password change can ever be detected")
		}
		if !contains(version.RequiredWith, "initial_password_wo") {
			t.Error("initial_password_wo_version must require initial_password_wo")
		}
	})

	t.Run("is mutually exclusive with initial_password", func(t *testing.T) {
		if !contains(wo.ConflictsWith, "initial_password") {
			t.Error("initial_password_wo must conflict with initial_password")
		}
		if !contains(old.ConflictsWith, "initial_password_wo") {
			t.Error("initial_password must conflict with initial_password_wo")
		}
	})

	// The version attribute is the only diff the provider can see for a write-only
	// password, so it must not be write-only itself.
	t.Run("version attribute is visible in state", func(t *testing.T) {
		if version.WriteOnly {
			t.Error("initial_password_wo_version must not be WriteOnly; it is the change signal and has to persist")
		}
	})

	t.Run("resource schema is valid", func(t *testing.T) {
		if err := r.InternalValidate(nil, true); err != nil {
			t.Fatalf("ad_user schema is invalid: %v", err)
		}
	})
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
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
