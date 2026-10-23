package ad

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/winrmhelper"
)

// userConfigWithoutUsername is the configuration from issue #59: every argument
// a typical ad_user sets, and no username.
func userConfigWithoutUsername() map[string]any {
	return map[string]any{
		"sam_account_name": "jdoe",
		"principal_name":   "jdoe@example.com",
		"display_name":     "Jane Doe",
		"given_name":       "Jane",
		"surname":          "Doe",
		"container":        "OU=Users,DC=example,DC=com",
	}
}

// An existing user whose configuration does not set username must plan no
// change for it. With `Default: false` the SDK decoded the default into the
// string "0" and planned `username = "Jane Doe" -> "0"` for every such user.
func TestResourceADUser_usernameUnsetPlansNoChange(t *testing.T) {
	r := resourceADUser()

	attrs := map[string]string{
		"id":       "f8b6c1d2-0000-0000-0000-000000000001",
		"username": "Jane Doe",
	}
	for k, v := range userConfigWithoutUsername() {
		attrs[k] = v.(string)
	}
	state := &terraform.InstanceState{ID: attrs["id"], Attributes: attrs}

	diff, err := r.Diff(context.Background(), state, terraform.NewResourceConfigRaw(userConfigWithoutUsername()), nil)
	if err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	if diff == nil {
		return
	}
	if attr, ok := diff.Attributes["username"]; ok {
		t.Errorf("unset username plans a change: %q -> %q", attr.Old, attr.New)
	}
}

// The other direction: a username that the configuration changes must still
// plan the change, or Computed would hide every rename.
func TestResourceADUser_usernameChangePlansChange(t *testing.T) {
	r := resourceADUser()

	attrs := map[string]string{
		"id":       "f8b6c1d2-0000-0000-0000-000000000001",
		"username": "Jane Doe",
	}
	config := userConfigWithoutUsername()
	for k, v := range config {
		attrs[k] = v.(string)
	}
	config["username"] = "Jane Smith"
	state := &terraform.InstanceState{ID: attrs["id"], Attributes: attrs}

	diff, err := r.Diff(context.Background(), state, terraform.NewResourceConfigRaw(config), nil)
	if err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	if diff == nil {
		t.Fatal("changed username plans no change")
	}
	attr, ok := diff.Attributes["username"]
	if !ok {
		t.Fatal("changed username plans no change")
	}
	if attr.Old != "Jane Doe" || attr.New != "Jane Smith" {
		t.Errorf("username diff = %q -> %q, want %q -> %q", attr.Old, attr.New, "Jane Doe", "Jane Smith")
	}
	if attr.RequiresNew {
		t.Error("username change forces a replacement, want an in-place rename")
	}
}

// On create, an unset username falls back to the part of the UPN before the
// "@", which GetUserFromResource implements. The default "0" made that fallback
// unreachable, so every such user was created with the CN "0".
func TestResourceADUser_usernameUnsetFallsBackToUPNPrefix(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceADUser().Schema, userConfigWithoutUsername())

	u, err := winrmhelper.GetUserFromResource(d)
	if err != nil {
		t.Fatalf("GetUserFromResource: %v", err)
	}
	if u.Username != "jdoe" {
		t.Errorf("Username = %q, want the UPN prefix %q", u.Username, "jdoe")
	}
}
