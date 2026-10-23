package winrmhelper

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"strings"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/structure"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// User represents an AD User
type User struct {
	GUID                   string `json:"ObjectGUID"`
	SAMAccountName         string `json:"SamAccountName"`
	PrincipalName          string `json:"UserPrincipalName"`
	City                   string
	Company                string
	Country                string
	Department             string
	Description            string
	DisplayName            string `json:"DisplayName"`
	DistinguishedName      string `json:"DistinguishedName"`
	Division               string
	EmailAddress           string
	EmployeeID             string
	EmployeeNumber         string
	Enabled                bool
	Fax                    string
	GivenName              string
	HomeDirectory          string
	HomeDrive              string
	HomePhone              string
	HomePage               string
	Initials               string
	MobilePhone            string
	Office                 string
	OfficePhone            string
	Organization           string
	OtherName              string
	POBox                  string
	PostalCode             string
	SID                    SID `json:"SID"`
	SmartcardLogonRequired bool
	State                  string
	StreetAddress          string
	Surname                string
	Title                  string
	TrustedForDelegation   bool
	UserAccountControl     int64 `json:"userAccountControl"`
	Password               string
	Container              string
	Domain                 string
	Username               string `json:"Name"`
	PasswordNeverExpires   bool
	CannotChangePassword   bool
	CustomAttributes       map[string]any
}

// newUserCommand renders the New-ADUser call for u, whose text fields hold
// values that SanitiseString has already escaped.
func newUserCommand(u *User) (string, error) {
	cmds := []string{fmt.Sprintf("New-ADUser -Passthru -Name %s", psQuoteSanitised(u.Username))}

	cmds = append(cmds, fmt.Sprintf("-CannotChangePassword $%t", u.CannotChangePassword))
	cmds = append(cmds, fmt.Sprintf("-PasswordNeverExpires $%t", u.PasswordNeverExpires))
	cmds = append(cmds, fmt.Sprintf("-Enabled $%t", u.Enabled))
	cmds = append(cmds, fmt.Sprintf("-SmartcardLogonRequired $%t", u.SmartcardLogonRequired))
	cmds = append(cmds, fmt.Sprintf("-TrustedForDelegation $%t", u.TrustedForDelegation))

	// Optional text parameters, in the order New-ADUser has always received
	// them. An empty value leaves the parameter out.
	appendText := func(params []userParam) {
		for _, p := range params {
			if p.value != "" {
				cmds = append(cmds, fmt.Sprintf("-%s %s", p.name, psQuoteSanitised(p.value)))
			}
		}
	}

	appendText([]userParam{
		{"SamAccountName", u.SAMAccountName},
		{"UserPrincipalName", u.PrincipalName},
	})

	if u.Password != "" {
		// psQuoteSanitised, the rendering SecretPassword registers, so what is
		// embedded and what is redacted cannot drift apart.
		cmds = append(cmds, fmt.Sprintf("-AccountPassword (ConvertTo-SecureString -AsPlainText %s -Force)", psQuoteSanitised(u.Password)))
	}

	appendText([]userParam{
		{"DisplayName", u.DisplayName},
		{"Path", u.Container},
		{"City", u.City},
		{"Company", u.Company},
		{"Country", strings.ToUpper(u.Country)},
		{"Department", u.Department},
		{"Description", u.Description},
		{"Division", u.Division},
		{"EmailAddress", u.EmailAddress},
		{"EmployeeID", u.EmployeeID},
		{"EmployeeNumber", u.EmployeeNumber},
		{"Fax", u.Fax},
		{"GivenName", u.GivenName},
		{"HomeDirectory", u.HomeDirectory},
		{"HomeDrive", u.HomeDrive},
		{"HomePhone", u.HomePhone},
		{"HomePage", u.HomePage},
		{"Initials", u.Initials},
		{"MobilePhone", u.MobilePhone},
		{"Office", u.Office},
		{"OfficePhone", u.OfficePhone},
		{"Organization", u.Organization},
		{"OtherName", u.OtherName},
		{"POBox", u.POBox},
		{"PostalCode", u.PostalCode},
		{"State", u.State},
		{"StreetAddress", u.StreetAddress},
		{"Surname", u.Surname},
		{"Title", u.Title},
	})

	if u.CustomAttributes != nil {
		attrs, err := u.getOtherAttributes()
		if err != nil {
			return "", err
		}
		cmds = append(cmds, fmt.Sprintf("-OtherAttributes %s", attrs))
	}

	return strings.Join(cmds, " "), nil
}

// userParam is one optional New-ADUser text parameter and its already
// escaped value.
type userParam struct{ name, value string }

// NewUser creates the user by running the New-ADUser powershell command
func (u *User) NewUser(conf *config.ProviderConf) (string, error) {
	if u.Username == "" {
		return "", fmt.Errorf("user principal name required")
	}

	log.Printf("Adding user with UPN: %q", u.PrincipalName)
	cmd, err := newUserCommand(u)
	if err != nil {
		return "", err
	}

	result, err := RunPSCommand(conf, "creating the user", cmd,
		JSONOutput(), SecretPassword(u.Password))
	if err != nil {
		if ErrorMentions(err, "AlreadyExists") {
			return "", fmt.Errorf("there is another User named %q", u.PrincipalName)
		}
		return "", err
	}

	user, err := unmarshallUser([]byte(result.Stdout), nil)
	if err != nil {
		return "", fmt.Errorf("error while unmarshalling user json document: %s", err)
	}

	return user.GUID, nil
}

// ModifyUser updates the AD user's details based on what's changed in the resource.
func (u *User) ModifyUser(d *schema.ResourceData, conf *config.ProviderConf) error {
	log.Printf("Modifying user: %q", u.PrincipalName)
	strKeyMap := map[string]string{
		"sam_account_name": "SamAccountName",
		"display_name":     "DisplayName",
		"principal_name":   "UserPrincipalName",
		"city":             "City",
		"company":          "Company",
		"country":          "Country",
		"department":       "Department",
		"description":      "Description",
		"division":         "Division",
		"email_address":    "EmailAddress",
		"employee_id":      "EmployeeID",
		"employee_number":  "EmployeeNumber",
		"fax":              "Fax",
		"given_name":       "GivenName",
		"home_directory":   "HomeDirectory",
		"home_drive":       "HomeDrive",
		"home_phone":       "HomePhone",
		"home_page":        "HomePage",
		"initials":         "Initials",
		"mobile_phone":     "MobilePhone",
		"office":           "Office",
		"office_phone":     "OfficePhone",
		"organization":     "Organization",
		"other_name":       "OtherName",
		"po_box":           "POBox",
		"postal_code":      "PostalCode",
		"state":            "State",
		"street_address":   "StreetAddress",
		"surname":          "Surname",
		"title":            "Title",
	}

	cmds := []string{fmt.Sprintf("Set-ADUser -Identity %q", u.GUID)}

	for k, param := range strKeyMap {
		if d.HasChange(k) {
			cmds = append(cmds, parameterArgument(param, SanitiseTFInput(d, k)))
		}
	}

	boolKeyMap := map[string]string{
		"cannot_change_password":    "CannotChangePassword",
		"password_never_expires":    "PasswordNeverExpires",
		"enabled":                   "Enabled",
		"smart_card_logon_required": "SmartcardLogonRequired",
		"trusted_for_delegation":    "TrustedForDelegation",
	}

	for k, param := range boolKeyMap {
		if d.HasChange(k) {
			value := d.Get(k).(bool)
			cmds = append(cmds, fmt.Sprintf("-%s $%t", param, value))
		}
	}

	if d.HasChange("custom_attributes") {
		oldValue, newValue := d.GetChange("custom_attributes")
		newMap, err := structure.ExpandJsonFromString(newValue.(string))
		if err != nil {
			return err
		}

		newSortedMap := SortInnerSlice(newMap)
		toClear := []string{}
		toReplace := []string{}
		toAdd := []string{}

		var oldSortedMap map[string]any
		if oldValue.(string) != "" {
			oldMap, err := structure.ExpandJsonFromString(oldValue.(string))
			if err != nil {
				return fmt.Errorf("while expanding CA json string %s: %s", oldValue.(string), err)
			}
			oldSortedMap = SortInnerSlice(oldMap)
		}

		for k, v := range oldSortedMap {
			if newVal, ok := newSortedMap[k]; ok {
				if !reflect.DeepEqual(v, newVal) {
					toReplace = append(toReplace, PSHashtableEntry(k, PSHashtableValue(newVal)))
				}
			} else {
				toClear = append(toClear, k)
			}
		}

		for k, newVal := range newSortedMap {
			if _, ok := oldSortedMap[k]; !ok {
				toAdd = append(toAdd, PSHashtableEntry(k, PSHashtableValue(newVal)))
			}
		}

		if len(toClear) > 0 {
			cmds = append(cmds, clearAttributesArgument(toClear))
		}

		if len(toReplace) > 0 {
			cmds = append(cmds, fmt.Sprintf(`-Replace @{%s}`, strings.Join(toReplace, ";")))
		}

		if len(toAdd) > 0 {
			cmds = append(cmds, fmt.Sprintf(`-Add @{%s}`, strings.Join(toAdd, ";")))
		}

	}

	if len(cmds) > 1 {
		if _, err := RunPSCommand(conf, "modifying the user", strings.Join(cmds, " ")); err != nil {
			return err
		}
	}

	// A write-only value is null in state, so it can never produce a diff of its
	// own — initial_password_wo_version is the only signal that it changed.
	if d.HasChange("initial_password") || d.HasChange("initial_password_wo_version") {
		cmd := resetPasswordCommand(u.GUID, u.Password)
		if _, err := RunPSCommand(conf, "setting the user's password", cmd, SecretPassword(u.Password)); err != nil {
			return err
		}
	}

	// username is the object's name (CN). Set-ADUser has no parameter for it, so
	// a change goes through Rename-ADObject, as it does for ad_group.
	if d.HasChange("username") {
		cmd := renameObjectCommand(u.GUID, d.Get("username").(string))
		if _, err := RunPSCommand(conf, "renaming the user", cmd); err != nil {
			return err
		}
	}

	if d.HasChange("container") {
		cmd := moveObjectCommand(u.GUID, d.Get("container").(string))
		if _, err := RunPSCommand(conf, "moving the user object", cmd); err != nil {
			return err
		}
	}

	return nil
}

// clearAttributesArgument renders -Clear for raw attribute names. -Clear takes
// an array, so the names are quoted and joined with commas; joined with ";", as
// they were, PowerShell ran every name after the first as a command of its own.
func clearAttributesArgument(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = psQuote(n)
	}
	return "-Clear " + strings.Join(quoted, ",")
}

// resetPasswordCommand renders the Set-ADAccountPassword call. The password has
// already been through SanitiseString, and SecretPassword registers the same
// rendering for redaction.
func resetPasswordCommand(guid, sanitisedPassword string) string {
	return fmt.Sprintf("Set-ADAccountPassword -Identity %q -Reset -NewPassword (ConvertTo-SecureString -AsPlainText %s -Force)", guid, psQuoteSanitised(sanitisedPassword))
}

// DeleteUser deletes an AD user by calling Remove-ADUser
func (u *User) DeleteUser(conf *config.ProviderConf) error {
	cmd := fmt.Sprintf("Remove-ADUser -Identity %s -Confirm:$false", u.GUID)
	_, err := RunPSCommand(conf, "removing the user", cmd)
	return CheckDeleteResult(err, "ADIdentityNotFoundException")
}

func (u *User) getOtherAttributes() (string, error) {
	out := []string{}
	for k, v := range u.CustomAttributes {
		var cleanValue string
		if reflect.ValueOf(v).Kind() == reflect.Slice {
			quotedStrings := make([]string, len(v.([]any)))
			for idx, s := range v.([]any) {
				// Using %q here will cause double quotes inside the string to be escaped with \"
				// which is not desirable in Powershell
				// GetString takes any and formats numbers and booleans itself;
				// asserting to string here panics on a custom attribute that is
				// not one, which JSON readily produces.
				quotedStrings[idx] = GetString(s)
			}
			cleanValue = strings.Join(quotedStrings, ",")
		} else {
			cleanValue = GetString(v)
		}
		out = append(out, PSHashtableEntry(k, cleanValue))
	}
	finalAttrString := strings.Join(out, ";")
	return fmt.Sprintf("@{%s}", finalAttrString), nil
}

// GetInitialPassword returns the password to apply to the user, taking it from
// initial_password_wo when that write-only argument is set and from
// initial_password otherwise. The two are mutually exclusive in the schema.
//
// A write-only value never reaches state, so d.Get returns nothing for it and it
// has to be read from the raw configuration. That configuration is only populated
// during plan and apply; on a refresh the value is absent, which is correct —
// there is nothing to apply then.
func GetInitialPassword(d *schema.ResourceData) (string, error) {
	woVal, diags := d.GetRawConfigAt(cty.GetAttrPath("initial_password_wo"))
	if diags.HasError() {
		// The attribute is absent from the raw config, which is the normal case
		// during a refresh. Fall back to the regular attribute.
		return SanitiseTFInput(d, "initial_password"), nil
	}

	if !woVal.IsNull() && woVal.IsKnown() {
		if woVal.Type() != cty.String {
			return "", fmt.Errorf("initial_password_wo has unexpected type %s, expected string", woVal.Type().FriendlyName())
		}
		return SanitiseString(woVal.AsString()), nil
	}

	return SanitiseTFInput(d, "initial_password"), nil
}

// GetUserFromResource returns a user struct built from Resource data
func GetUserFromResource(d *schema.ResourceData) (*User, error) {
	password, err := GetInitialPassword(d)
	if err != nil {
		return nil, err
	}

	user := User{
		GUID:                   d.Id(),
		SAMAccountName:         SanitiseTFInput(d, "sam_account_name"),
		PrincipalName:          SanitiseTFInput(d, "principal_name"),
		DisplayName:            SanitiseTFInput(d, "display_name"),
		Container:              SanitiseTFInput(d, "container"),
		Password:               password,
		Enabled:                d.Get("enabled").(bool),
		PasswordNeverExpires:   d.Get("password_never_expires").(bool),
		CannotChangePassword:   d.Get("cannot_change_password").(bool),
		City:                   SanitiseTFInput(d, "city"),
		Company:                SanitiseTFInput(d, "company"),
		Country:                SanitiseTFInput(d, "country"),
		Department:             SanitiseTFInput(d, "department"),
		Description:            SanitiseTFInput(d, "description"),
		Division:               SanitiseTFInput(d, "division"),
		EmailAddress:           SanitiseTFInput(d, "email_address"),
		EmployeeID:             SanitiseTFInput(d, "employee_id"),
		EmployeeNumber:         SanitiseTFInput(d, "employee_number"),
		Fax:                    SanitiseTFInput(d, "fax"),
		GivenName:              SanitiseTFInput(d, "given_name"),
		HomeDirectory:          SanitiseTFInput(d, "home_directory"),
		HomeDrive:              SanitiseTFInput(d, "home_drive"),
		HomePhone:              SanitiseTFInput(d, "home_phone"),
		HomePage:               SanitiseTFInput(d, "home_page"),
		Initials:               SanitiseTFInput(d, "initials"),
		MobilePhone:            SanitiseTFInput(d, "mobile_phone"),
		Office:                 SanitiseTFInput(d, "office"),
		OfficePhone:            SanitiseTFInput(d, "office_phone"),
		Organization:           SanitiseTFInput(d, "organization"),
		OtherName:              SanitiseTFInput(d, "other_name"),
		POBox:                  SanitiseTFInput(d, "po_box"),
		PostalCode:             SanitiseTFInput(d, "postal_code"),
		SmartcardLogonRequired: d.Get("smart_card_logon_required").(bool),
		State:                  SanitiseTFInput(d, "state"),
		StreetAddress:          SanitiseTFInput(d, "street_address"),
		Surname:                SanitiseTFInput(d, "surname"),
		Title:                  SanitiseTFInput(d, "title"),
		TrustedForDelegation:   d.Get("trusted_for_delegation").(bool),
		Username:               SanitiseTFInput(d, "username"),
	}
	if user.PrincipalName != "" {
		tokens := strings.Split(user.PrincipalName, "@")
		// set user.Username to the first token in the split if it user.Username is empty
		if user.Username == "" {
			user.Username = tokens[0]
		}
		if len(tokens) > 1 {
			user.Domain = tokens[1]
		}
	}

	ca, ok := d.Get("custom_attributes").(string)
	if ok && len(ca) > 0 {
		user.CustomAttributes = make(map[string]any)
		customAttributes, err := structure.ExpandJsonFromString(ca)
		if err != nil {
			return nil, fmt.Errorf("while unmarshalling custom attributes JSON doc: %s", err)
		}
		user.CustomAttributes = customAttributes
	}

	return &user, nil
}

// userLookupCommand renders the Get-ADUser call for a raw identity: a GUID
// from state, or the user_id of the data source, which may also be a SID, DN
// or SAM account name.
func userLookupCommand(identity string) string {
	return fmt.Sprintf("Get-ADUser -identity %s -properties *", psQuote(identity))
}

// GetUserFromHost returns a User struct based on data
// retrieved from the AD Domain Controller.
func GetUserFromHost(conf *config.ProviderConf, identity string, customAttributes []string) (*User, error) {
	cmd := userLookupCommand(identity)
	result, err := RunPSCommand(conf, "retrieving the user", cmd, JSONOutput())
	if err != nil {
		return nil, err
	}

	u, err := unmarshallUser([]byte(result.Stdout), customAttributes)
	if err != nil {
		return nil, fmt.Errorf("error while unmarshalling user json document: %s", err)
	}
	return u, nil
}

// unmarshallUser unmarshalls the incoming byte array containing JSON
// into a User structure and populates all fields based on the data
// extracted.
func unmarshallUser(input []byte, customAttributes []string) (*User, error) {
	var user User
	err := json.Unmarshal(input, &user)
	if err != nil {
		log.Printf("[DEBUG] Failed to unmarshall json document with error %q, document was: %s", err, string(input))
		return nil, fmt.Errorf("failed while unmarshalling json response: %s", err)
	}
	if user.GUID == "" {
		return nil, fmt.Errorf("invalid data while unmarshalling User data, json doc was: %s", string(input))
	}
	if user.PrincipalName != "" {
		tokens := strings.Split(user.PrincipalName, "@")
		if user.Username == "" {
			user.Username = tokens[0]
		}
		if len(tokens) > 1 {
			user.Domain = tokens[1]
		}
	}

	commaIdx := strings.Index(user.DistinguishedName, ",")
	user.Container = user.DistinguishedName[commaIdx+1:]

	var accountControlMap = map[string]int64{
		"disabled":               0x00000002,
		"password_never_expires": 0x00010000,
	}

	user.Enabled = !(user.UserAccountControl&accountControlMap["disabled"] != 0)
	user.PasswordNeverExpires = user.UserAccountControl&accountControlMap["password_never_expires"] != 0

	// CannotChangePassword is deliberately NOT derived from userAccountControl.
	// Active Directory implements it as a deny ACE on the Change Password right,
	// and Microsoft documents PASSWD_CANT_CHANGE (0x40) as a flag that cannot be
	// set directly and is not reflected in the attribute — so deriving it always
	// produced false regardless of the account's real setting. Get-ADUser
	// -properties * returns CannotChangePassword as its own property, and the
	// User struct has no json tag on that field, so encoding/json already fills
	// it in case-insensitively. The derivation was overwriting the correct value
	// with a constant false.
	//
	// PasswordNeverExpires above is a genuine userAccountControl bit
	// (DONT_EXPIRE_PASSWORD, 0x10000) and stays derived.

	if customAttributes == nil {
		return &user, nil
	}

	var userMapIntf any
	err = json.Unmarshal(input, &userMapIntf)
	if err != nil {
		log.Printf("[DEBUG] Failed to unmarshall json document with error %q, document was: %s", err, string(input))
		return nil, fmt.Errorf("failed while unmarshalling json response: %s", err)
	}

	userMap := userMapIntf.(map[string]any)
	user.CustomAttributes = make(map[string]any)
	for _, property := range customAttributes {
		if val, ok := userMap[property]; ok {
			user.CustomAttributes[property] = val
		}
	}

	return &user, nil
}
