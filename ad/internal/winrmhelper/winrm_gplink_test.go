package winrmhelper

import "testing"

const (
	upperGUID = "9CB8219C-31FF-4A85-A7A3-9BCBB6A41D02"
	lowerGUID = "9cb8219c-31ff-4a85-a7a3-9bcbb6a41d02"
	otherGUID = "11111111-2222-3333-4444-555555555555"
	ouDN      = "OU=Test,DC=example,DC=com"
)

// TestFindGPLinkIsCaseInsensitive is the guard for the actual defect: Active
// Directory returns GUIDs in whichever casing it stored them, so comparing them
// case-sensitively intermittently reports a linked GPO as unlinked.
func TestFindGPLinkIsCaseInsensitive(t *testing.T) {
	for _, c := range []struct {
		name       string
		storedGUID string
		lookupGUID string
	}{
		{"same casing", upperGUID, upperGUID},
		{"directory stored it lowercase", lowerGUID, upperGUID},
		{"configuration used lowercase", upperGUID, lowerGUID},
		{"both lowercase", lowerGUID, lowerGUID},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := findGPLink([][]string{{c.storedGUID, "1", "0", ouDN}}, c.lookupGUID)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatalf("link stored as %q was not found when looked up as %q", c.storedGUID, c.lookupGUID)
			}
			if got.Target != ouDN {
				t.Errorf("Target = %q, want %q", got.Target, ouDN)
			}
		})
	}
}

func TestFindGPLinkOptions(t *testing.T) {
	for _, c := range []struct {
		options           string
		enforced, enabled bool
	}{
		{"0", false, true},
		{"1", false, false},
		{"2", true, true},
		{"3", true, false},
	} {
		t.Run("options "+c.options, func(t *testing.T) {
			got, err := findGPLink([][]string{{upperGUID, "2", c.options, ouDN}}, upperGUID)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("link not found")
			}
			if got.Enforced != c.enforced || got.Enabled != c.enabled {
				t.Errorf("options %q gave enforced=%v enabled=%v, want %v/%v",
					c.options, got.Enforced, got.Enabled, c.enforced, c.enabled)
			}
			if got.Order != 2 {
				t.Errorf("Order = %d, want 2", got.Order)
			}
		})
	}
}

func TestFindGPLinkMisses(t *testing.T) {
	t.Run("unlinked GPO returns nil without error", func(t *testing.T) {
		got, err := findGPLink([][]string{{otherGUID, "1", "0", ouDN}}, upperGUID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Errorf("got %+v, want nil for a GPO that is not linked", got)
		}
	})

	t.Run("empty list returns nil without error", func(t *testing.T) {
		got, err := findGPLink(nil, upperGUID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Errorf("got %+v, want nil", got)
		}
	})

	t.Run("unparseable order is an error, not a miss", func(t *testing.T) {
		got, err := findGPLink([][]string{{upperGUID, "not-a-number", "0", ouDN}}, upperGUID)
		if err == nil {
			t.Fatalf("expected an error, got %+v", got)
		}
	})

	// The match must be on the whole GUID, not a prefix — otherwise one GPO's
	// link could be reported for another.
	t.Run("prefix does not match", func(t *testing.T) {
		got, err := findGPLink([][]string{{upperGUID[:8], "1", "0", ouDN}}, upperGUID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Errorf("a truncated GUID must not match; got %+v", got)
		}
	})
}
