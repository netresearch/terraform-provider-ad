package winrmhelper

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"
	"github.com/packer-community/winrmcp/winrmcp"
)

// SID is a common structure by all "security principals". This means domains, users, computers, and groups.
// The structure we get from powershell contains more fields, but we're only interested in the Value.
type SID struct {
	Value string `json:"Value"`
}

// LocalPSSession struct
type LocalPSSession struct {
	powerShell string
}

// NewLocalPSSession create new local session
func NewLocalPSSession() *LocalPSSession {
	ps, _ := exec.LookPath("powershell.exe")
	return &LocalPSSession{
		powerShell: ps,
	}
}

const defaultFailedCode = 1

// ExecutePScmd will execute the powershell command using exec
func (l *LocalPSSession) ExecutePScmd(args ...string) (stdout string, stderr string, exitCode int, err error) {
	var outbuf, errbuf bytes.Buffer
	cmd := exec.Command(l.powerShell, args...)
	cmd.Stdout = &outbuf
	cmd.Stderr = &errbuf

	err = cmd.Run()
	stdout = outbuf.String()
	stderr = errbuf.String()

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			ws := exitError.Sys().(syscall.WaitStatus)
			exitCode = ws.ExitStatus()
		} else {
			exitCode = defaultFailedCode
			if stderr == "" {
				stderr = err.Error()
			}
		}
	} else {
		// success, exitCode should be 0 if go is ok
		ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
		exitCode = ws.ExitStatus()
	}
	return
}

// SanitiseTFInput returns the value of a resource field after passing it through SanitiseString
func SanitiseTFInput(d *schema.ResourceData, key string) string {
	return SanitiseString(d.Get(key).(string))

}

// SanitiseString returns the value of a string after some basic sanitisation checks
// to protect ourselves from command injection
func SanitiseString(key string) string {
	cleanupReplacer := strings.NewReplacer(
		"`", "``",
		`"`, "`\"",
		"$", "`$",
		"\x00", "`0",
		"\x07", "`a",
		"\x08", "`b",
		"\x1f", "`e",
		"\x0c", "`f",
		"\n", "`n",
		"\r", "`r",
		"\t", "`t",
		"\v", "`v",
	)
	out := cleanupReplacer.Replace(key)
	log.Printf("[DEBUG] sanitising key %q to: %s", key, out)
	return out
}

// SetMachineExtensionNames will add the necessary GUIDs to the GPO's gPCMachineExtensionNames attribute.
// These are required for the security settings part of a GPO to work.
func SetMachineExtensionNames(conf *config.ProviderConf, gpoDN, value string) error {
	cmd := fmt.Sprintf(`Set-ADObject -Identity "%s" -Replace @{gPCMachineExtensionNames="%s"}`, gpoDN, value)
	psOpts := CreatePSCommandOpts{
		JSONOutput:      false,
		ForceArray:      false,
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: conf.IsPassCredentialsEnabled(),
		Username:        conf.Settings.WinRMUsername,
		Password:        conf.Settings.WinRMPassword,
		Server:          conf.IdentifyDomainController(),
	}
	psCmd := NewPSCommand([]string{cmd}, psOpts)
	result, err := psCmd.Run(conf)
	if err != nil {
		return fmt.Errorf("error while setting machine extension names for GPO %q: %s", gpoDN, err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("command to set machine extension names for GPO %q failed, stderr: %s, stdout: %s", gpoDN, result.StdErr, result.Stdout)
	}
	return nil
}

// CheckDeleteResult turns the outcome of a destructive PowerShell command into
// an error, or into nil when the object was already gone.
//
// PSCommand.Run reports an error only for transport failures. A command the
// directory REFUSES — removing an account protected from accidental deletion,
// removing a GPO without the rights — returns no error and a non-zero exit
// code, so a caller that only looks at err reports success for a destroy that
// did not happen, and Terraform drops the resource from state while the object
// still exists.
//
// alreadyGone is the exception text that means the object is not there any more,
// which is a successful destroy: "ADIdentityNotFoundException" for AD objects,
// "GpoWithNameNotFound" for group policies.
func CheckDeleteResult(result *PSCommandResult, err error, alreadyGone, what string) error {
	if err != nil {
		if strings.Contains(err.Error(), alreadyGone) {
			return nil
		}
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("while removing %s: stderr: %s", what, result.StdErr)
	}
	return nil
}

// PSHashtableEntry formats one `key=value` pair of a PowerShell hashtable
// literal. The key is single-quoted because PowerShell parses a bare hyphenated
// key such as ms-DS-ConsistencyGuid as an arithmetic expression, and AD
// attribute names are routinely hyphenated. The value is passed through
// unchanged, already quoted by the caller.
//
// Every hashtable this package builds goes through here, so the three call sites
// cannot drift apart again — they had, and only one of them quoted its key.
func PSHashtableEntry(key, value string) string {
	// SanitiseString does not touch apostrophes, and an apostrophe would close
	// the single-quoted literal early. PowerShell escapes one by doubling it.
	escapedKey := strings.ReplaceAll(SanitiseString(key), "'", "''")
	return fmt.Sprintf("'%s'=%s", escapedKey, value)
}

// PSHashtableValue renders a value taken from a SortInnerSlice map for use in a
// PowerShell hashtable.
//
// Those values have ALREADY been through GetString, which returns them quoted,
// so they are passed through rather than quoted again. Quoting here a second
// time produces `""Chief""`, which makes the Set-ADUser hashtable invalid — the
// -Replace branch did exactly that, and the -Add branch, which looked
// inconsistent beside it, was the correct one.
func PSHashtableValue(v any) string {
	switch typed := v.(type) {
	case []string:
		return strings.Join(typed, ",")
	case string:
		return typed
	default:
		// SortInnerSlice only ever produces string and []string. Anything else
		// is a programming error; format it rather than panic.
		return GetString(v)
	}
}

func GetString(v any) string {
	var out string
	kind := reflect.ValueOf(v).Kind()
	switch kind {
	case reflect.String:
		out = SanitiseString(v.(string))
	case reflect.Float64:
		// 'f' rather than 'E': Active Directory stores what we send verbatim, so
		// scientific notation would write a numeric attribute as "1E+06".
		out = strconv.FormatFloat(v.(float64), 'f', -1, 64)
	case reflect.Int64:
		out = strconv.FormatInt(v.(int64), 10)
	case reflect.Bool:
		out = strconv.FormatBool(v.(bool))
	}
	return fmt.Sprintf(`"%s"`, out)
}

// SortInnerSlice is used to sort multivalued custom attributes.
// Custom attributes can be single valued or multi valued. Multi-value attribute values are represented by a json
// array that gets converted to a list. It's not guaranteed that the order of the values returned by windows
// will match the order set by the user in the config, so we just check the members of the custom attributes map
// and if a slice is found then it's sorted before we compare it.
func SortInnerSlice(m map[string]any) map[string]any {
	for k, v := range m {
		if reflect.ValueOf(v).Kind() == reflect.Slice {
			newVal := make([]string, len(v.([]any)))
			for idx, attr := range v.([]any) {
				newVal[idx] = GetString(attr)
			}
			sort.Strings(newVal)
			m[k] = newVal
		} else {
			m[k] = GetString(v)
		}
	}
	return m
}

func UploadFiletoSYSVOL(conf *config.ProviderConf, cpClient *winrmcp.Winrmcp, buf io.Reader, destPath string) error {
	tmpPathCmd := NewPSCommand([]string{"$randompath=[System.IO.Path]::GetRandomFileName(); echo $env:TMP\\$randompath"}, CreatePSCommandOpts{
		ForceArray:      false,
		JSONOutput:      false,
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: false,
		SkipCredPrefix:  true,
		SkipCredSuffix:  true,
	})
	tmpPathResult, err := tmpPathCmd.Run(conf)
	if err != nil {
		return fmt.Errorf("while renaming GPO: %s", err)
	} else if tmpPathResult != nil && tmpPathResult.ExitCode != 0 {
		return fmt.Errorf("while renaming GPO stderr: %s", tmpPathResult.StdErr)
	}
	tmpPath := tmpPathResult.Stdout

	err = cpClient.Write(tmpPath, buf)
	if err != nil {
		return fmt.Errorf("error while writing ini file to %q: %s", destPath, err)
	}

	toks := strings.Split(destPath, `\`)
	x := toks[:len(toks)-1]
	destDir := strings.Join(x, `\`)
	mdCmd := fmt.Sprintf(`$check=Test-Path "%s"; if (!$check)  {md "%s"}`, destDir, destDir)
	domainName := conf.Settings.DomainName
	if conf.Settings.KrbRealm == domainName {
		domainName = "$env:computername"
	}
	mdPSComamnd := NewPSCommand([]string{mdCmd}, CreatePSCommandOpts{
		ExecLocally:     conf.IsConnectionTypeLocal(),
		JSONOutput:      false,
		ForceArray:      false,
		PassCredentials: conf.IsPassCredentialsEnabled(),
		InvokeCommand:   conf.IsPassCredentialsEnabled(),
		Username:        conf.Settings.WinRMUsername,
		Password:        conf.Settings.WinRMPassword,
		Server:          domainName,
	})
	mdOutput, err := mdPSComamnd.Run(conf)
	if err != nil {
		return fmt.Errorf("while renaming GPO: %s", err)
	} else if mdOutput != nil && mdOutput.ExitCode != 0 {
		return fmt.Errorf("while renaming GPO stderr: %s", mdOutput.StdErr)
	}

	cpCmd := fmt.Sprintf(`Copy-Item "%s" "%s"; Remove-Item "%s"`, tmpPath, destPath, tmpPath)
	cpPSComamnd := NewPSCommand([]string{cpCmd}, CreatePSCommandOpts{
		ExecLocally:     conf.IsConnectionTypeLocal(),
		JSONOutput:      false,
		ForceArray:      false,
		PassCredentials: conf.IsPassCredentialsEnabled(),
		InvokeCommand:   conf.IsPassCredentialsEnabled(),
		Username:        conf.Settings.WinRMUsername,
		Password:        conf.Settings.WinRMPassword,
		Server:          domainName,
	})
	cpOutput, err := cpPSComamnd.Run(conf)
	if err != nil {
		return fmt.Errorf("while renaming GPO: %s", err)
	} else if cpOutput != nil && cpOutput.ExitCode != 0 {
		return fmt.Errorf("while renaming GPO stderr: %s", cpOutput.StdErr)
	}

	return nil
}
