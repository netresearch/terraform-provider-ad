package ad

import (
	"fmt"
	"uuid"
)

// parseGUID accepts only the canonical hyphenated form of a GUID, the form
// Active Directory returns.
//
// The length check is what makes it strict. uuid.Parse also accepts the URN
// form, the unhyphenated 32-character form and the brace-wrapped form, all of
// which Active Directory would echo back to us canonicalised — leaving a
// permanent diff against the value in the configuration, since gpo_guid is
// ForceNew and only case is suppressed. Rejecting those at validation time is
// the behaviour the provider has always had.
func parseGUID(s string) error {
	if len(s) != 36 {
		return fmt.Errorf("uuid string is wrong length")
	}
	if _, err := uuid.Parse(s); err != nil {
		return err
	}
	return nil
}
