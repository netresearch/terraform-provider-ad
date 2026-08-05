package winrmhelper

import "testing"

func TestGetMembershipListQuotesMembers(t *testing.T) {
	// Members may be sAMAccountNames, SIDs, GUIDs or DNs. DNs contain commas
	// and often spaces (CN=First Last,OU=...) - unquoted they break the
	// PowerShell parameter binding of -Members (PositionalParameterNotFound,
	// "System.Object[]"). Every member must therefore be individually quoted.
	members := []*GroupMember{
		{GUID: "annegret.mueller"},
		{GUID: "CN=Philipp Beck,OU=LSBS,OU=Kunden,DC=netresearch,DC=nr"},
	}

	got := getMembershipList(members)
	want := `"annegret.mueller","CN=Philipp Beck,OU=LSBS,OU=Kunden,DC=netresearch,DC=nr"`
	if got != want {
		t.Fatalf("getMembershipList() = %s, want %s", got, want)
	}
}
