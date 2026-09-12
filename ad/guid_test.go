package ad

import "testing"

// TestParseGUIDAcceptsOnlyTheCanonicalForm pins the strictness the provider had
// while it used hashicorp/go-uuid, whose ParseUUID required exactly 36
// characters with hyphens at 8, 13, 18 and 23. The stdlib uuid.Parse this
// replaced it with accepts three further spellings of the same value; each of
// them is listed here as rejected, so dropping the length check in parseGUID
// fails this test rather than silently widening what gpo_guid accepts.
func TestParseGUIDAcceptsOnlyTheCanonicalForm(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		valid bool
	}{
		{"canonical", "11111111-2222-3333-4444-555555555555", true},
		{"canonical uppercase", "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", true},
		{"real gpo guid", "6AC1786C-016F-11D2-945F-00C04FB984F9", true},

		// Accepted by uuid.Parse, rejected by hashicorp/go-uuid's ParseUUID.
		{"urn form", "urn:uuid:11111111-2222-3333-4444-555555555555", false},
		{"unhyphenated", "11111111222233334444555555555555", false},
		{"brace wrapped", "{11111111-2222-3333-4444-555555555555}", false},

		// Rejected by both.
		{"empty", "", false},
		{"not a uuid", "not-a-uuid", false},
		{"one char short", "11111111-2222-3333-4444-55555555555", false},
		{"non hex digit", "11111111-2222-3333-4444-55555555555g", false},
		{"trailing space", "11111111-2222-3333-4444-555555555555 ", false},
		{"leading space", " 11111111-2222-3333-4444-555555555555", false},
		{"hyphens misplaced", "111111112-222-3333-4444-555555555555", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := parseGUID(tc.in)
			if tc.valid && err != nil {
				t.Errorf("parseGUID(%q) = %v, want accepted", tc.in, err)
			}
			if !tc.valid && err == nil {
				t.Errorf("parseGUID(%q) = nil, want rejected", tc.in)
			}
		})
	}
}
