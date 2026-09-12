package winrmhelper

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type GroupMembership struct {
	GroupGUID    string
	GroupMembers []*GroupMember
}

type GroupMember struct {
	SamAccountName string `json:"SamAccountName"`
	DN             string `json:"DistinguishedName"`
	GUID           string `json:"ObjectGUID"`
	Name           string `json:"Name"`
	SID            SID    `json:"SID"`
}

// Identifiers returns every form by which this member can be named in a
// configuration. The schema documents all of them as interchangeable, and
// Get-ADGroupMember returns all of them, so a member read back from the
// directory can be recognised whichever one the practitioner wrote.
//
// Empty forms are skipped: a member built from configuration carries only the
// one string the practitioner supplied.
func (g *GroupMember) Identifiers() []string {
	out := make([]string, 0, 5)
	for _, id := range []string{g.GUID, g.DN, g.SamAccountName, g.Name, g.SID.Value} {
		if id != "" {
			out = append(out, id)
		}
	}
	return out
}

// Matches reports whether other names the same directory object as g. Any
// identifier form matching any other counts, because a configuration may use a
// SAM account name where the directory answers with a GUID — comparing only
// GUIDs made every such configuration produce a permanent diff.
//
// Comparison is case-insensitive: Active Directory treats these identifiers
// that way, and GUIDs in particular come back in whatever casing was stored.
func (g *GroupMember) Matches(other *GroupMember) bool {
	for _, a := range g.Identifiers() {
		for _, b := range other.Identifiers() {
			if strings.EqualFold(a, b) {
				return true
			}
		}
	}
	return false
}

func groupExistsInList(g *GroupMember, memberList []*GroupMember) bool {
	for _, item := range memberList {
		if g.Matches(item) {
			return true
		}
	}
	return false
}

// ReconcileMemberIdentifiers decides what to write to state for the members the
// directory reports, given what the configuration currently holds.
//
// A member the configuration already names keeps that spelling, whichever
// identifier form it is. Anything else — a member added outside Terraform — is
// written as its GUID, so it still shows up as drift to be removed.
//
// Without this the read wrote GUIDs unconditionally. A configuration naming
// members by SAM account name or distinguished name therefore disagreed with
// state on every single plan, and Terraform proposed removing and re-adding
// every member forever.
func ReconcileMemberIdentifiers(actual []*GroupMember, configured []string) []string {
	out := make([]string, 0, len(actual))

	for _, member := range actual {
		out = append(out, preferConfiguredIdentifier(member, configured))
	}

	return out
}

func preferConfiguredIdentifier(member *GroupMember, configured []string) string {
	for _, candidate := range configured {
		if candidate == "" {
			continue
		}
		if member.Matches(&GroupMember{GUID: candidate}) {
			return candidate
		}
	}

	return member.GUID
}

func diffGroupMemberLists(expectedMembers, existingMembers []*GroupMember) ([]*GroupMember, []*GroupMember) {
	var toAdd, toRemove []*GroupMember
	for _, member := range expectedMembers {
		if !groupExistsInList(member, existingMembers) {
			toAdd = append(toAdd, member)
		}
	}

	for _, member := range existingMembers {
		if !groupExistsInList(member, expectedMembers) {
			toRemove = append(toRemove, member)
		}
	}

	return toAdd, toRemove
}

func unmarshalGroupMembership(input []byte) ([]*GroupMember, error) {
	var gm []*GroupMember
	err := json.Unmarshal(input, &gm)
	if err != nil {
		return nil, err
	}
	if len(gm) > 0 && gm[0].GUID == "" {
		return nil, fmt.Errorf("invalid data while unmarshalling group membership data, json doc was: %s", string(input))
	}
	return gm, nil
}

func getMembershipList(g []*GroupMember) string {
	out := []string{}
	for _, member := range g {
		// Quote each member: unquoted values containing spaces or commas
		// (any DN of the form CN=First Last,OU=...) break PowerShell
		// parameter binding of -Members ("System.Object[]" /
		// PositionalParameterNotFound).
		out = append(out, fmt.Sprintf("%q", member.GUID))
	}

	return strings.Join(out, ",")
}

func (g *GroupMembership) getGroupMembers(conf *config.ProviderConf) ([]*GroupMember, error) {
	cmd := fmt.Sprintf("Get-ADGroupMember -Identity %q", g.GroupGUID)
	result, err := RunPSCommand(conf, "running Get-ADGroupMember", cmd, JSONOutput(), ForceArray())
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(result.Stdout) == "" {
		return []*GroupMember{}, nil
	}

	gm, err := unmarshalGroupMembership([]byte(result.Stdout))
	if err != nil {
		return nil, fmt.Errorf("while unmarshalling group membership response: %s", err)
	}

	return gm, nil
}

// maxMemberListLength caps the rendered member list of a single
// Add-/Remove-ADGroupMember call.
//
// Windows limits a command line to 8191 characters. The command is transported
// as UTF-16LE base64, which inflates it by roughly 8/3, so the raw command has
// to stay near 3000 characters. 2000 leaves room for the operation name, the
// group GUID and the switches, and is deliberately conservative: members are
// identified by GUID, SID, SAM account name or distinguished name, and a DN of
// the form CN=First Last,OU=Department,DC=example,DC=com is an order of
// magnitude longer than a GUID. Chunking by member count instead — as the
// upstream patch does, at 50 — holds for GUIDs and still overflows for DNs.
const maxMemberListLength = 2000

// chunkMembers splits members so each chunk renders to at most budget
// characters. A single member longer than the budget is emitted in a chunk of
// its own rather than dropped: the command will fail, but with the directory's
// own error rather than silently missing a member.
func chunkMembers(members []*GroupMember, budget int) [][]*GroupMember {
	if len(members) == 0 {
		return nil
	}

	var chunks [][]*GroupMember
	var current []*GroupMember
	length := 0

	for _, m := range members {
		// Each rendered member costs its quoted length plus the joining comma.
		cost := len(fmt.Sprintf("%q", m.GUID)) + 1

		if len(current) > 0 && length+cost > budget {
			chunks = append(chunks, current)
			current = nil
			length = 0
		}

		current = append(current, m)
		length += cost
	}

	return append(chunks, current)
}

func (g *GroupMembership) bulkGroupMembersOp(conf *config.ProviderConf, operation string, members []*GroupMember) error {
	if len(members) == 0 {
		return nil
	}

	for _, chunk := range chunkMembers(members, maxMemberListLength) {
		memberList := getMembershipList(chunk)
		cmd := fmt.Sprintf("%s -Identity %q %s -Confirm:$false", operation, g.GroupGUID, memberList)

		if _, err := RunPSCommand(conf, fmt.Sprintf("running %s", operation), cmd); err != nil {
			return err
		}
	}

	return nil
}

func (g *GroupMembership) addGroupMembers(conf *config.ProviderConf, members []*GroupMember) error {
	return g.bulkGroupMembersOp(conf, "Add-ADGroupMember", members)
}

func (g *GroupMembership) removeGroupMembers(conf *config.ProviderConf, members []*GroupMember) error {
	return g.bulkGroupMembersOp(conf, "Remove-ADGroupMember", members)
}

func (g *GroupMembership) Update(conf *config.ProviderConf, expected []*GroupMember) error {
	existing, err := g.getGroupMembers(conf)
	if err != nil {
		return err
	}

	toAdd, toRemove := diffGroupMemberLists(expected, existing)
	err = g.addGroupMembers(conf, toAdd)
	if err != nil {
		return err
	}

	err = g.removeGroupMembers(conf, toRemove)
	if err != nil {
		return err
	}

	return nil
}

func (g *GroupMembership) Create(conf *config.ProviderConf) error {
	if len(g.GroupMembers) == 0 {
		return nil
	}

	memberList := getMembershipList(g.GroupMembers)
	cmds := []string{fmt.Sprintf("Add-ADGroupMember -Identity %q -Members %s", g.GroupGUID, memberList)}
	if _, err := RunPSCommand(conf, "running Add-ADGroupMember", strings.Join(cmds, " ")); err != nil {
		return err
	}

	return nil
}

func (g *GroupMembership) Delete(conf *config.ProviderConf) error {
	subCmdOpt := NewPSCommandOpts(conf, SkipCredentialPreamble())
	subcmd := NewPSCommand([]string{fmt.Sprintf("Get-AdGroupMember %q", g.GroupGUID)}, subCmdOpt)
	cmd := fmt.Sprintf("Remove-ADGroupMember %q -Members (%s) -Confirm:$false", g.GroupGUID, subcmd.String())

	// A group that has no members left makes Remove-ADGroupMember reject its
	// empty -Members list, which for a destroy is the state we wanted.
	_, err := RunPSCommand(conf, "running Remove-ADGroupMember", cmd)
	return CheckDeleteResult(err, "InvalidData")
}

func NewGroupMembershipFromHost(conf *config.ProviderConf, groupID string) (*GroupMembership, error) {
	result := &GroupMembership{
		GroupGUID: groupID,
	}

	gm, err := result.getGroupMembers(conf)
	if err != nil {
		return nil, err
	}
	result.GroupMembers = gm

	return result, nil
}

func NewGroupMembershipFromState(d *schema.ResourceData) (*GroupMembership, error) {
	groupID := d.Get("group_id").(string)
	members := d.Get("group_members").(*schema.Set)
	result := &GroupMembership{
		GroupGUID:    groupID,
		GroupMembers: []*GroupMember{},
	}

	for _, m := range members.List() {
		if m == "" {
			continue
		}
		newMember := &GroupMember{
			GUID: m.(string),
		}

		result.GroupMembers = append(result.GroupMembers, newMember)
	}
	return result, nil
}
