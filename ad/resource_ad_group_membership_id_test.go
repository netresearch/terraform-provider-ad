package ad

import "testing"

// TestMembershipGroupIDRoundTrip checks that Read recovers the configured
// group_id from the id that Create stores, for every group_id form the schema
// accepts, including those that contain an underscore.
func TestMembershipGroupIDRoundTrip(t *testing.T) {
	groupIDs := []string{
		"9CB8219C-31FF-4A85-A7A3-9BCBB6A41D02",
		"S-1-5-21-1004336348-1177238915-682003330-512",
		"app_admins",
		"app__admins_",
		"CN=app_admins,OU=Groups_EU,DC=example,DC=com",
	}
	for _, groupID := range groupIDs {
		id := membershipID(groupID)
		if got := membershipGroupID(id); got != groupID {
			t.Errorf("membershipGroupID(%q) = %q, want %q", id, got, groupID)
		}
	}
}

// TestMembershipGroupIDTakesAnImportIDWithoutSuffixWhole covers an id handed to
// `terraform import` without the GUID suffix: the whole id is the group_id.
func TestMembershipGroupIDTakesAnImportIDWithoutSuffixWhole(t *testing.T) {
	ids := []string{
		"9CB8219C-31FF-4A85-A7A3-9BCBB6A41D02",
		"app_admins",
		"app_9CB8219C31FF4A85A7A39BCBB6A41D02",
	}
	for _, id := range ids {
		if got := membershipGroupID(id); got != id {
			t.Errorf("membershipGroupID(%q) = %q, want the whole id", id, got)
		}
	}
}

// TestMembershipGroupIDReadsTheDocumentedImportID pins the import example in
// docs/resources/group_membership.md.
func TestMembershipGroupIDReadsTheDocumentedImportID(t *testing.T) {
	id := "9CB8219C-31FF-4A85-A7A3-9BCBB6A41D02_E9079B50-95C5-4101-8400-E01CC83CF53B"
	want := "9CB8219C-31FF-4A85-A7A3-9BCBB6A41D02"
	if got := membershipGroupID(id); got != want {
		t.Errorf("membershipGroupID(%q) = %q, want %q", id, got, want)
	}
}
