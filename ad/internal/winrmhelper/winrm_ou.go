package winrmhelper

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// OrgUnit is a structure used to represent an AD OrganizationalUnit object
type OrgUnit struct {
	Name              string
	Description       string
	Path              string
	Protected         bool `json:"ProtectedFromAccidentalDeletion"`
	DistinguishedName string
	GUID              string `json:"ObjectGuid"`
}

// NewOrgUnitFromResource returns a new OrgUnit struct populated from resource data
func NewOrgUnitFromResource(d *schema.ResourceData) *OrgUnit {
	ou := OrgUnit{
		Description:       SanitiseTFInput(d, "description"),
		Name:              SanitiseTFInput(d, "name"),
		Path:              SanitiseTFInput(d, "path"),
		DistinguishedName: SanitiseTFInput(d, "dn"),
		GUID:              SanitiseTFInput(d, "guid"),
	}
	protected := d.Get("protected").(bool)
	ou.Protected = protected
	return &ou
}

// NewOrgUnitFromHost returns a new OrgUnit struct populated from data we get from
// the domain controller
func NewOrgUnitFromHost(conf *config.ProviderConf, guid, name, path string) (*OrgUnit, error) {
	var cmd string
	if guid != "" {
		cmd = fmt.Sprintf("Get-ADObject -Properties * -Identity %q", guid)
	} else if name != "" && path != "" {
		cmd = fmt.Sprintf("Get-ADObject -Properties * -Name %q -Path %q", name, path)
	} else {
		return nil, fmt.Errorf("invalid inputs, dn or a combination of path and name are required")
	}
	result, err := RunPSCommand(conf, "retrieving the OU", cmd, JSONOutput())
	if err != nil {
		return nil, err
	}
	ou, err := unmarshallOU([]byte(result.Stdout))
	if err != nil {
		return nil, err
	}
	ou.Path = strings.TrimPrefix(ou.DistinguishedName, fmt.Sprintf("OU=%s,", ou.Name))

	return ou, nil
}

// Create creates a new OU in the AD tree
func (o *OrgUnit) Create(conf *config.ProviderConf) (string, error) {

	cmd := "New-ADOrganizationalUnit -Passthru"
	if o.Name == "" {
		return "", fmt.Errorf("missing required attribute name, cannot create OU")
	}
	cmd = fmt.Sprintf("%s -Name %q", cmd, o.Name)

	if o.Description != "" {
		cmd = fmt.Sprintf("%s -Description %q", cmd, o.Description)
	}

	if o.Path != "" {
		cmd = fmt.Sprintf("%s -Path %q", cmd, o.Path)
	}

	cmd = fmt.Sprintf("%s -ProtectedFromAccidentalDeletion:$%t", cmd, o.Protected)
	result, err := RunPSCommand(conf, "creating the OU", cmd, JSONOutput())
	if err != nil {
		return "", err
	}
	ou, err := unmarshallOU([]byte(result.Stdout))
	if err != nil {
		return "", err
	}

	return ou.GUID, nil
}

// Update updates an existing OU in the AD tree
func (o *OrgUnit) Update(conf *config.ProviderConf, changes map[string]any) error {
	if o.DistinguishedName == "" {
		return fmt.Errorf("Cannot update OU with name %q, distiguished name is empty", o.Name)
	}
	cmd := fmt.Sprintf("Set-ADOrganizationalUnit -Identity %q", o.DistinguishedName)

	keyMap := map[string]string{
		"display_name": "DisplayName",
		"description":  "Description",
	}

	for k, v := range changes {
		if paramName, ok := keyMap[k]; ok {
			cmd = fmt.Sprintf("%s -%s %q", cmd, paramName, v.(string))
		}
	}

	if cmd != "Set-ADOrganizationalUnit -Identity" {
		if _, err := RunPSCommand(conf, "modifying the OU", cmd); err != nil {
			return err
		}
	}

	if path, ok := changes["path"]; ok {
		var unprotected bool
		if o.Protected == true {
			cmd := fmt.Sprintf("Set-ADOrganizationalUnit -Identity %q -ProtectedFromAccidentalDeletion:$false", o.GUID)
			if _, err := RunPSCommand(conf, "unprotecting the OU object", cmd); err != nil {
				return err
			}
			unprotected = true
		}

		cmd := fmt.Sprintf("Move-ADObject -Identity %q -TargetPath %q", o.GUID, path.(string))
		if _, err := RunPSCommand(conf, "moving the OU object", cmd); err != nil {
			return err
		}

		if unprotected == true {
			cmd := fmt.Sprintf("Set-ADOrganizationalUnit -Identity %q -ProtectedFromAccidentalDeletion:$true", o.GUID)
			if _, err := RunPSCommand(conf, "protecting the OU object", cmd); err != nil {
				return err
			}
		}
	}

	if protected, ok := changes["protected"]; ok {
		cmd = fmt.Sprintf("Set-ADObject -Identity %s -ProtectedFromAccidentalDeletion:$%t", o.GUID, protected.(bool))
		if _, err := RunPSCommand(conf, "updating the OU's protected status", cmd); err != nil {
			return err
		}
	}

	if name, ok := changes["name"]; ok {
		cmd = fmt.Sprintf("Rename-ADObject -Identity %q %q ", o.GUID, name.(string))
		if _, err := RunPSCommand(conf, "renaming the OU", cmd); err != nil {
			return err
		}
	}
	return nil
}

// Delete deletes an existing OU from an AD tree
func (o *OrgUnit) Delete(conf *config.ProviderConf) error {
	if o.DistinguishedName == "" {
		return fmt.Errorf("Cannot remove OU with name %q, distiguished name is empty", o.Name)
	}
	var cmds []string
	subCmds := []string{
		fmt.Sprintf("Get-ADObject -Properties * -Identity %q", o.DistinguishedName),
		"Set-ADObject -ProtectedFromAccidentalDeletion:$false -Passthru",
		"Remove-ADOrganizationalUnit -confirm:$false",
	}

	psOpts := NewPSCommandOpts(conf, SkipCredentialPreamble())

	for _, subCmd := range subCmds {
		cmds = append(cmds, NewPSCommand([]string{subCmd}, psOpts).String())
	}

	cmd := strings.Join(cmds, "|")
	if _, err := RunPSCommand(conf, "removing the OU", cmd, ComposedCommand()); err != nil {
		return err
	}
	return nil
}

func unmarshallOU(input []byte) (*OrgUnit, error) {
	var ou OrgUnit
	err := json.Unmarshal(input, &ou)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshall json document with error %q, document was: %s", err, string(input))
		return nil, fmt.Errorf("failed while unmarshalling json response: %s", err)
	}
	if ou.GUID == "" {
		return nil, fmt.Errorf("invalid data while unmarshalling OU data, json doc was: %s", string(input))
	}
	return &ou, nil

}
