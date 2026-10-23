package winrmhelper

import "testing"

// TestRenameUserCommandQuotesOnce pins the PowerShell text of a rename. The
// name is escaped once, by SanitiseString; quoting it with %q added Go escapes
// on top, so a `"` ended the PowerShell string and a `\` reached AD doubled.
func TestRenameUserCommandQuotesOnce(t *testing.T) {
	for _, c := range []struct {
		name string
		want string
	}{
		{`Jane Doe`, `Rename-ADObject -Identity "` + upperGUID + `" -NewName "Jane Doe"`},
		{`Doe, Jane`, `Rename-ADObject -Identity "` + upperGUID + `" -NewName "Doe, Jane"`},
		{`Jane "JJ" Doe`, `Rename-ADObject -Identity "` + upperGUID + `" -NewName "Jane ` + "`" + `"JJ` + "`" + `" Doe"`},
		{`Doe\Jane`, `Rename-ADObject -Identity "` + upperGUID + `" -NewName "Doe\Jane"`},
		{`$env:USERNAME`, `Rename-ADObject -Identity "` + upperGUID + `" -NewName "` + "`" + `$env:USERNAME"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := renameUserCommand(upperGUID, SanitiseString(c.name)); got != c.want {
				t.Errorf("renameUserCommand(%q)\n got: %s\nwant: %s", c.name, got, c.want)
			}
		})
	}
}
