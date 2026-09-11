package ad

import "testing"

// TestGroupMembersAllowsEmptySet guards the absence of MinItems on
// group_members. With MinItems set, a group that is deliberately empty cannot be
// expressed at all — the practitioner has to delete the resource instead, which
// is a different thing and loses the declaration that the group should have no
// members.
func TestGroupMembersAllowsEmptySet(t *testing.T) {
	r, ok := Provider().ResourcesMap["ad_group_membership"]
	if !ok {
		t.Fatal("resource ad_group_membership is not registered")
	}

	members, ok := r.Schema["group_members"]
	if !ok {
		t.Fatal("attribute group_members does not exist")
	}

	if members.MinItems != 0 {
		t.Errorf("group_members has MinItems %d; an empty group must be expressible", members.MinItems)
	}
}
