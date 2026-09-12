package ad

import (
	"strings"
	"testing"
)

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

// TestMembershipIDIsSplittableAndCanonical asserts on what the resource builds,
// not on a copy of it. An earlier version of this test rebuilt the expression in
// the test body, so it stayed green when the resource stopped rendering the
// canonical form — and when the GUID was dropped from the id altogether.
//
// uuid.UUID is a [16]byte. A %s verb on it renders raw bytes rather than the
// canonical text unless String is reached, and that form compiles and vets, so
// the defect is available and has to be pinned here. Read reads only the token
// before the first underscore, so the raw-byte form does not corrupt Read; what
// it corrupts is the resource id itself, which lands in serialised state and is
// what `terraform import` must be handed back.
func TestMembershipIDIsSplittableAndCanonical(t *testing.T) {
	const group = "6AC1786C-016F-11D2-945F-00C04FB984F9"

	id := membershipID(group)

	parts := strings.Split(id, "_")
	if len(parts) != 2 {
		t.Fatalf("id splits into %d parts on the underscore, want 2: %q", len(parts), id)
	}
	if parts[0] != group {
		t.Errorf("Read would take %q as the group GUID, want %q", parts[0], group)
	}
	if err := parseGUID(parts[1]); err != nil {
		t.Errorf("the unique half is not a canonical GUID: %v (%q)", err, parts[1])
	}

	// Two calls must differ, or the id is not unique per membership.
	if other := membershipID(group); other == id {
		t.Errorf("two ids are identical: %q", id)
	}
}

// TestGPOGUIDValidatorRejectsNonGUIDs reaches the ValidateFunc the way Terraform
// does: through the provider's resource map, not by calling resourceADGPLink
// directly. Going through the map also pins the registration — repointing
// "ad_gplink" at another resource otherwise leaves the whole suite green.
//
// Without this test, deleting the validation from resource_ad_gplink.go left the
// suite green too: its only coverage was an acceptance test behind TF_ACC, and
// the workflow that runs on a pull request runs `make test` and `go mod verify`,
// neither of which sets TF_ACC.
//
// That acceptance test's input, "something-horribly-wrong", is 24 characters, so
// it exercises only the length branch. The cases here cover both branches and the
// three spellings a bare uuid.Parse would accept.
func TestGPOGUIDValidatorRejectsNonGUIDs(t *testing.T) {
	gplink, ok := Provider().ResourcesMap["ad_gplink"]
	if !ok {
		t.Fatal("the provider does not register ad_gplink")
	}
	validate := gplink.Schema["gpo_guid"].ValidateFunc
	if validate == nil {
		t.Fatal("gpo_guid has no ValidateFunc")
	}

	for _, tc := range []struct {
		name  string
		in    string
		valid bool
	}{
		{"canonical", "6AC1786C-016F-11D2-945F-00C04FB984F9", true},
		{"urn form", "urn:uuid:11111111-2222-3333-4444-555555555555", false},
		{"unhyphenated", "11111111222233334444555555555555", false},
		{"brace wrapped", "{11111111-2222-3333-4444-555555555555}", false},
		{"non hex digit", "11111111-2222-3333-4444-55555555555g", false},
		{"too short", "something-horribly-wrong", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, errs := validate(tc.in, "gpo_guid")
			if tc.valid && len(errs) != 0 {
				t.Errorf("validate(%q) returned %v, want accepted", tc.in, errs)
			}
			if !tc.valid && len(errs) == 0 {
				t.Errorf("validate(%q) returned no error, want rejected", tc.in)
			}
		})
	}
}
