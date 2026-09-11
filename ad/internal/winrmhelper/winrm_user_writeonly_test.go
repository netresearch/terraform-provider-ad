package winrmhelper

import (
	"testing"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// passwordSchema is the subset of ad_user that GetInitialPassword reads.
func passwordSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"initial_password": {
			Type:      schema.TypeString,
			Optional:  true,
			Sensitive: true,
		},
		"initial_password_wo": {
			Type:      schema.TypeString,
			Optional:  true,
			WriteOnly: true,
		},
		"initial_password_wo_version": {
			Type:     schema.TypeInt,
			Optional: true,
		},
	}
}

// dataWithConfig builds ResourceData carrying a raw configuration, which is the
// only place a write-only value ever appears. attrs values may be cty.NullVal.
func dataWithConfig(t *testing.T, state map[string]string, attrs map[string]cty.Value) *schema.ResourceData {
	t.Helper()

	r := &schema.Resource{Schema: passwordSchema()}

	full := map[string]cty.Value{
		"initial_password":            cty.NullVal(cty.String),
		"initial_password_wo":         cty.NullVal(cty.String),
		"initial_password_wo_version": cty.NullVal(cty.Number),
	}
	for k, v := range attrs {
		if _, ok := full[k]; !ok {
			t.Fatalf("attribute %q is not part of the test schema", k)
		}
		full[k] = v
	}

	is := &terraform.InstanceState{
		ID:         "test-guid",
		Attributes: state,
		RawConfig:  cty.ObjectVal(full),
	}
	return r.Data(is)
}

func TestGetInitialPassword(t *testing.T) {
	t.Run("write-only value wins", func(t *testing.T) {
		d := dataWithConfig(t,
			map[string]string{"initial_password": "from-state"},
			map[string]cty.Value{"initial_password_wo": cty.StringVal("from-write-only")},
		)

		got, err := GetInitialPassword(d)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "from-write-only" {
			t.Errorf("got %q, want the write-only value", got)
		}
	})

	t.Run("falls back to initial_password when write-only is null", func(t *testing.T) {
		d := dataWithConfig(t,
			map[string]string{"initial_password": "regular"},
			map[string]cty.Value{"initial_password": cty.StringVal("regular")},
		)

		got, err := GetInitialPassword(d)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "regular" {
			t.Errorf("got %q, want %q", got, "regular")
		}
	})

	t.Run("empty when neither is set", func(t *testing.T) {
		d := dataWithConfig(t, map[string]string{}, map[string]cty.Value{})

		got, err := GetInitialPassword(d)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	// The write-only value is interpolated into a PowerShell command exactly like
	// the regular one, so it has to go through the same sanitiser. Without this
	// the new path would be a command injection hole the old path does not have.
	t.Run("write-only value is sanitised", func(t *testing.T) {
		d := dataWithConfig(t,
			map[string]string{},
			map[string]cty.Value{"initial_password_wo": cty.StringVal("a\"b$c`d")},
		)

		got, err := GetInitialPassword(d)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := SanitiseString("a\"b$c`d")
		if got != want {
			t.Errorf("got %q, want %q — the write-only value must pass through SanitiseString", got, want)
		}
		if got == "a\"b$c`d" {
			t.Error("value was returned unsanitised")
		}
	})

	// On a refresh there is no configuration at all. The helper must not fail;
	// it falls back to whatever state holds.
	t.Run("null raw config falls back without error", func(t *testing.T) {
		r := &schema.Resource{Schema: passwordSchema()}
		d := r.Data(&terraform.InstanceState{
			ID:         "test-guid",
			Attributes: map[string]string{"initial_password": "from-state"},
			RawConfig:  cty.NullVal(cty.EmptyObject),
		})

		got, err := GetInitialPassword(d)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "from-state" {
			t.Errorf("got %q, want the state value", got)
		}
	})
}
