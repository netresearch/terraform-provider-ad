package winrmhelper

import (
	"fmt"
	"testing"
)

// adUserJSON mimics what Get-ADUser -identity <guid> -properties * returns for
// the fields this test cares about.
func adUserJSON(uac int64, cannotChangePassword bool) []byte {
	return []byte(fmt.Sprintf(`{
		"ObjectGUID": "9CB8219C-31FF-4A85-A7A3-9BCBB6A41D02",
		"SamAccountName": "testuser",
		"DistinguishedName": "CN=Test User,OU=Staff,DC=example,DC=com",
		"userAccountControl": %d,
		"CannotChangePassword": %t
	}`, uac, cannotChangePassword))
}

// TestCannotChangePasswordComesFromTheDirectory is the guard for the defect.
// Active Directory implements "user cannot change password" as a deny ACE on the
// Change Password right, not as a userAccountControl bit — Microsoft documents
// PASSWD_CANT_CHANGE (0x40) as not directly settable. Deriving the field from
// userAccountControl therefore overwrote the value Get-ADUser had already
// reported, and always yielded false.
func TestCannotChangePasswordComesFromTheDirectory(t *testing.T) {
	for _, c := range []struct {
		name string
		uac  int64
		// what the directory reports for the account
		reported bool
	}{
		{"set, with no corresponding UAC bit", 0x0200, true},
		{"clear, with no corresponding UAC bit", 0x0200, false},
		{"set, while the account is also disabled", 0x0202, true},
		{"set, while the password never expires", 0x10200, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			u, err := unmarshallUser(adUserJSON(c.uac, c.reported), nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if u.CannotChangePassword != c.reported {
				t.Errorf("CannotChangePassword = %v, want %v — the value must come from the directory, not from userAccountControl",
					u.CannotChangePassword, c.reported)
			}
		})
	}
}

// TestAccountControlDerivedFieldsStillWork pins the two flags that genuinely are
// userAccountControl bits, so removing the third derivation cannot quietly take
// them with it.
func TestAccountControlDerivedFieldsStillWork(t *testing.T) {
	for _, c := range []struct {
		name                  string
		uac                   int64
		enabled, neverExpires bool
	}{
		{"normal account", 0x0200, true, false},
		{"disabled account", 0x0202, false, false},
		{"password never expires", 0x10200, true, true},
		{"disabled and never expires", 0x10202, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			u, err := unmarshallUser(adUserJSON(c.uac, false), nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if u.Enabled != c.enabled {
				t.Errorf("Enabled = %v, want %v", u.Enabled, c.enabled)
			}
			if u.PasswordNeverExpires != c.neverExpires {
				t.Errorf("PasswordNeverExpires = %v, want %v", u.PasswordNeverExpires, c.neverExpires)
			}
		})
	}
}
