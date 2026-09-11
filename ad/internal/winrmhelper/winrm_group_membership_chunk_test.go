package winrmhelper

import (
	"fmt"
	"strings"
	"testing"
)

func members(n int, id func(int) string) []*GroupMember {
	out := make([]*GroupMember, n)
	for i := range out {
		out[i] = &GroupMember{GUID: id(i)}
	}
	return out
}

func guidID(i int) string { return fmt.Sprintf("9CB8219C-31FF-4A85-A7A3-%012d", i) }

func dnID(i int) string {
	return fmt.Sprintf("CN=Given Family Name %d,OU=Department,OU=Division,DC=example,DC=com", i)
}

// TestChunkMembersRespectsBudget is the guard for the defect: one unbounded
// Add-/Remove-ADGroupMember command overruns the Windows command-line limit as
// soon as a group has enough members, and the operation fails outright.
func TestChunkMembersRespectsBudget(t *testing.T) {
	for _, c := range []struct {
		name string
		n    int
		id   func(int) string
	}{
		{"500 GUIDs", 500, guidID},
		{"500 distinguished names", 500, dnID},
		{"5000 distinguished names", 5000, dnID},
	} {
		t.Run(c.name, func(t *testing.T) {
			all := members(c.n, c.id)
			chunks := chunkMembers(all, maxMemberListLength)

			seen := 0
			for i, chunk := range chunks {
				if len(chunk) == 0 {
					t.Fatalf("chunk %d is empty", i)
				}
				seen += len(chunk)

				rendered := getMembershipList(chunk)
				// A chunk may exceed the budget only when it holds a single
				// member that is itself over budget.
				if len(rendered) > maxMemberListLength && len(chunk) > 1 {
					t.Errorf("chunk %d renders %d characters, over the %d budget, with %d members",
						i, len(rendered), maxMemberListLength, len(chunk))
				}
			}

			if seen != c.n {
				t.Errorf("chunks hold %d members, want all %d — chunking must not drop anyone", seen, c.n)
			}
		})
	}
}

// TestChunkMembersPreservesOrderAndIdentity guards against a chunker that keeps
// the count right while corrupting the contents.
func TestChunkMembersPreservesOrderAndIdentity(t *testing.T) {
	all := members(250, dnID)

	var flat []string
	for _, chunk := range chunkMembers(all, maxMemberListLength) {
		for _, m := range chunk {
			flat = append(flat, m.GUID)
		}
	}

	if len(flat) != len(all) {
		t.Fatalf("got %d members back, want %d", len(flat), len(all))
	}
	for i := range all {
		if flat[i] != all[i].GUID {
			t.Fatalf("member %d is %q, want %q", i, flat[i], all[i].GUID)
		}
	}
}

func TestChunkMembersEdgeCases(t *testing.T) {
	t.Run("empty input yields no chunks", func(t *testing.T) {
		if got := chunkMembers(nil, maxMemberListLength); len(got) != 0 {
			t.Errorf("got %d chunks, want none", len(got))
		}
	})

	t.Run("a small group stays a single command", func(t *testing.T) {
		got := chunkMembers(members(10, guidID), maxMemberListLength)
		if len(got) != 1 {
			t.Errorf("10 members produced %d chunks, want 1 — chunking must not split what fits", len(got))
		}
	})

	// A member longer than the whole budget must still be attempted rather than
	// silently dropped or spun on forever.
	t.Run("oversized single member is kept", func(t *testing.T) {
		huge := &GroupMember{GUID: "CN=" + strings.Repeat("x", maxMemberListLength*2)}
		got := chunkMembers([]*GroupMember{huge}, maxMemberListLength)
		if len(got) != 1 || len(got[0]) != 1 {
			t.Fatalf("got %v, want one chunk holding the one member", got)
		}
		if got[0][0].GUID != huge.GUID {
			t.Error("the oversized member was altered")
		}
	})
}
