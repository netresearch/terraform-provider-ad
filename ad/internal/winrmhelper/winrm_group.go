package winrmhelper

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Group represents an AD Group
type Group struct {
	GUID              string `json:"ObjectGUID"`
	SAMAccountName    string `json:"SamAccountName"`
	Name              string `json:"Name"`
	ScopeNum          int    `json:"GroupScope"`
	CategoryNum       int    `json:"GroupCategory"`
	DistinguishedName string `json:"DistinguishedName"`
	Scope             string
	Category          string
	Container         string
	Description       string
	SID               SID `json:"SID"`
}

// newGroupCommand renders the New-ADGroup call for g, whose fields hold values
// that SanitiseString has already escaped.
func newGroupCommand(g *Group) string {
	cmds := []string{fmt.Sprintf("New-ADGroup -Passthru -Name %s -GroupScope %s -GroupCategory %s -Path %s",
		psQuoteSanitised(g.Name), psQuoteSanitised(g.Scope), psQuoteSanitised(g.Category), psQuoteSanitised(g.Container))}

	if g.SAMAccountName != "" {
		cmds = append(cmds, fmt.Sprintf("-SamAccountName %s", psQuoteSanitised(g.SAMAccountName)))
	}

	if g.Description != "" {
		cmds = append(cmds, fmt.Sprintf("-Description %s", psQuoteSanitised(g.Description)))
	}
	return strings.Join(cmds, " ")
}

// AddGroup creates a new group
func (g *Group) AddGroup(conf *config.ProviderConf) (string, error) {
	log.Printf("[DEBUG] Adding group with name %q", g.Name)
	result, err := RunPSCommand(conf, "creating the group", newGroupCommand(g), JSONOutput())
	if err != nil {
		if ErrorMentions(err, "already exists") {
			return "", fmt.Errorf("there is another group named %q", g.Name)
		}
		return "", err
	}

	group, err := unmarshallGroup([]byte(result.Stdout))
	if err != nil {
		return "", fmt.Errorf("error while unmarshalling group json document: %s", err)
	}

	return group.GUID, nil
}

// ModifyGroup updates an existing group
func (g *Group) ModifyGroup(d *schema.ResourceData, conf *config.ProviderConf) error {
	KeyMap := map[string]string{
		"sam_account_name": "SamAccountName",
		"scope":            "GroupScope",
		"category":         "GroupCategory",
		"description":      "Description",
	}

	cmds := []string{fmt.Sprintf("Set-ADGroup -Identity %q", g.GUID)}

	for k, param := range KeyMap {
		if d.HasChange(k) {
			value := SanitiseTFInput(d, k)
			if value == "" {
				value = "$null"
			} else {
				value = psQuoteSanitised(value)
			}
			cmds = append(cmds, fmt.Sprintf(`-%s %s`, param, value))
		}
	}

	if len(cmds) > 1 {
		if _, err := RunPSCommand(conf, "modifying the group", strings.Join(cmds, " ")); err != nil {
			return err
		}
	}

	if d.HasChange("name") {
		cmd := renameObjectCommand(g.GUID, d.Get("name").(string))
		if _, err := RunPSCommand(conf, "renaming the group", cmd); err != nil {
			return err
		}
	}

	if d.HasChange("container") {
		cmd := moveObjectCommand(g.GUID, d.Get("container").(string))
		if _, err := RunPSCommand(conf, "moving the group object", cmd); err != nil {
			return err
		}
	}

	return nil
}

// DeleteGroup removes a group
func (g *Group) DeleteGroup(conf *config.ProviderConf) error {
	cmd := fmt.Sprintf("Remove-ADGroup -Identity %s -Confirm:$false", g.GUID)
	_, err := RunPSCommand(conf, "removing the group", cmd)
	return CheckDeleteResult(err, "ADIdentityNotFoundException")
}

// GetGroupFromResource returns a Group struct built from Resource data
func GetGroupFromResource(d *schema.ResourceData) *Group {
	g := Group{
		Name:           SanitiseTFInput(d, "name"),
		SAMAccountName: SanitiseTFInput(d, "sam_account_name"),
		Container:      SanitiseTFInput(d, "container"),
		Scope:          SanitiseTFInput(d, "scope"),
		Category:       SanitiseTFInput(d, "category"),
		GUID:           SanitiseString(d.Id()),
		Description:    SanitiseTFInput(d, "description"),
	}

	return &g
}

// groupLookupCommand renders the Get-ADGroup call for a raw identity: a GUID
// from state, or the group_id of the data source, which may also be a SID, DN
// or SAM account name.
func groupLookupCommand(identity string) string {
	return fmt.Sprintf("Get-ADGroup -identity %s -properties *", psQuote(identity))
}

// GetGroupFromHost returns a Group struct based on data
// retrieved from the AD Controller.
func GetGroupFromHost(conf *config.ProviderConf, identity string) (*Group, error) {
	cmd := groupLookupCommand(identity)
	result, err := RunPSCommand(conf, "retrieving the group", cmd, JSONOutput())
	if err != nil {
		return nil, err
	}

	g, err := unmarshallGroup([]byte(result.Stdout))
	if err != nil {
		return nil, fmt.Errorf("error while unmarshalling group json document: %s", err)
	}

	return g, nil
}

// unmarshallGroup unmarshalls the incoming byte array containing JSON
// into a Group structure and populates all fields based on the data
// extracted.
func unmarshallGroup(input []byte) (*Group, error) {
	var g Group
	err := json.Unmarshal(input, &g)
	if err != nil {
		log.Printf("[DEBUG] Failed to unmarshall json document with error %q, document was: %s", err, string(input))
		return nil, fmt.Errorf("failed while unmarshalling json response: %s", err)
	}
	if g.GUID == "" {
		return nil, fmt.Errorf("invalid data while unmarshalling Group data, json doc was: %s", string(input))
	}
	scopes := []string{"domainlocal", "global", "universal"}
	categories := []string{"distribution", "security"}

	g.Scope = scopes[g.ScopeNum]
	g.Category = categories[g.CategoryNum]

	commaIdx := strings.Index(g.DistinguishedName, ",")
	g.Container = g.DistinguishedName[commaIdx+1:]

	return &g, nil
}
