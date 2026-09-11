package winrmhelper

import (
	"strings"
	"testing"
)

// jdoe is one directory object as Get-ADGroupMember reports it: every identifier
// form filled in.
func jdoe() *GroupMember {
	return &GroupMember{
		SamAccountName: "jdoe",
		DN:             "CN=John Doe,OU=Staff,DC=example,DC=com",
		GUID:           "9CB8219C-31FF-4A85-A7A3-9BCBB6A41D02",
		Name:           "John Doe",
		SID:            SID{Value: "S-1-5-21-1111111111-2222222222-3333333333-1001"},
	}
}

// configured is a member as it arrives from the configuration: one identifier
// and nothing else.
func configured(id string) *GroupMember { return &GroupMember{GUID: id} }

// TestGroupMemberMatchesEveryIdentifierForm is the guard for the perpetual diff.
// The schema documents GUID, SID, distinguished name and SAM account name as
// interchangeable, but the comparison only ever looked at GUID — so a
// configuration using any other form never matched what the directory returned,
// and every plan proposed removing and re-adding the member.
func TestGroupMemberMatchesEveryIdentifierForm(t *testing.T) {
	actual := jdoe()

	for _, c := range []struct {
		name, id string
	}{
		{"GUID", "9CB8219C-31FF-4A85-A7A3-9BCBB6A41D02"},
		{"GUID in other casing", "9cb8219c-31ff-4a85-a7a3-9bcbb6a41d02"},
		{"SAM account name", "jdoe"},
		{"SAM account name in other casing", "JDoe"},
		{"distinguished name", "CN=John Doe,OU=Staff,DC=example,DC=com"},
		{"common name", "John Doe"},
		{"SID", "S-1-5-21-1111111111-2222222222-3333333333-1001"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if !actual.Matches(configured(c.id)) {
				t.Errorf("a member configured as %q did not match the directory's answer; this is the perpetual diff", c.id)
			}
			if !configured(c.id).Matches(actual) {
				t.Errorf("matching is not symmetric for %q", c.id)
			}
		})
	}
}

func TestGroupMemberDoesNotMatchOtherObjects(t *testing.T) {
	actual := jdoe()

	for _, c := range []struct{ name, id string }{
		{"different SAM account name", "asmith"},
		{"different GUID", "11111111-2222-3333-4444-555555555555"},
		{"different DN", "CN=Alice Smith,OU=Staff,DC=example,DC=com"},
		{"different SID", "S-1-5-21-1111111111-2222222222-3333333333-9999"},
		{"a prefix of the SAM account name", "jdo"},
		{"empty string", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if actual.Matches(configured(c.id)) {
				t.Errorf("%q must not match John Doe — a false match would silently keep the wrong member", c.id)
			}
		})
	}
}

// TestDiffGroupMemberListsAcrossIdentifierForms is the behaviour that matters:
// with the configuration and the directory naming the same people differently,
// there must be nothing to add and nothing to remove.
func TestDiffGroupMemberListsAcrossIdentifierForms(t *testing.T) {
	fromDirectory := []*GroupMember{jdoe()}

	t.Run("same member, named by SAM account name", func(t *testing.T) {
		toAdd, toRemove := diffGroupMemberLists([]*GroupMember{configured("jdoe")}, fromDirectory)
		if len(toAdd) != 0 || len(toRemove) != 0 {
			t.Errorf("got %d to add and %d to remove; the member is already there under another name", len(toAdd), len(toRemove))
		}
	})

	t.Run("a genuinely new member is still added", func(t *testing.T) {
		toAdd, toRemove := diffGroupMemberLists(
			[]*GroupMember{configured("jdoe"), configured("asmith")},
			fromDirectory,
		)
		if len(toAdd) != 1 || toAdd[0].GUID != "asmith" {
			t.Errorf("got %v to add, want just asmith", toAdd)
		}
		if len(toRemove) != 0 {
			t.Errorf("got %d to remove, want none", len(toRemove))
		}
	})

	t.Run("a member dropped from the configuration is still removed", func(t *testing.T) {
		toAdd, toRemove := diffGroupMemberLists(nil, fromDirectory)
		if len(toAdd) != 0 {
			t.Errorf("got %d to add, want none", len(toAdd))
		}
		if len(toRemove) != 1 {
			t.Fatalf("got %d to remove, want 1", len(toRemove))
		}
	})
}

// TestReconcileMemberIdentifiers pins what the read writes back to state.
func TestReconcileMemberIdentifiers(t *testing.T) {
	fromDirectory := []*GroupMember{jdoe()}

	for _, c := range []struct {
		name       string
		configured []string
		want       string
	}{
		{"SAM account name is kept", []string{"jdoe"}, "jdoe"},
		{"distinguished name is kept", []string{"CN=John Doe,OU=Staff,DC=example,DC=com"}, "CN=John Doe,OU=Staff,DC=example,DC=com"},
		{"SID is kept", []string{"S-1-5-21-1111111111-2222222222-3333333333-1001"}, "S-1-5-21-1111111111-2222222222-3333333333-1001"},
		{"the practitioner's casing is kept", []string{"JDoe"}, "JDoe"},
		{"an unconfigured member falls back to its GUID", []string{"someone-else"}, "9CB8219C-31FF-4A85-A7A3-9BCBB6A41D02"},
		{"no configuration at all falls back to the GUID", nil, "9CB8219C-31FF-4A85-A7A3-9BCBB6A41D02"},
		{"an empty entry is ignored", []string{"", "jdoe"}, "jdoe"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := ReconcileMemberIdentifiers(fromDirectory, c.configured)
			if len(got) != 1 {
				t.Fatalf("got %d identifiers, want 1", len(got))
			}
			if got[0] != c.want {
				t.Errorf("got %q, want %q", got[0], c.want)
			}
		})
	}

	// Drift: someone added a member outside Terraform. It must appear, so the
	// next plan proposes removing it.
	t.Run("a member added outside Terraform still appears", func(t *testing.T) {
		stranger := &GroupMember{GUID: "11111111-2222-3333-4444-555555555555", SamAccountName: "asmith"}
		got := ReconcileMemberIdentifiers([]*GroupMember{jdoe(), stranger}, []string{"jdoe"})

		if len(got) != 2 {
			t.Fatalf("got %v, want both members", got)
		}
		if !strings.EqualFold(got[1], stranger.GUID) {
			t.Errorf("the unconfigured member came back as %q, want its GUID", got[1])
		}
	})
}
