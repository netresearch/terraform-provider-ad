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
