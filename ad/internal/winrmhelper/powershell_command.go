package winrmhelper

import (
	"encoding/xml"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/masterzen/winrm"
)

type CreatePSCommandOpts struct {
	ExecLocally     bool
	ForceArray      bool
	InvokeCommand   bool
	JSONOutput      bool
	PassCredentials bool
	Password        string
	Server          string
	SkipCredPrefix  bool
	SkipCredSuffix  bool
	Username        string
}

// NewPSCommandOpts returns the options with every field that is derived from
// the provider connection already filled in. Callers set only what differs —
// JSONOutput, ForceArray, a Server other than the domain controller, and the
// credential-prefix switches.
//
// These five fields were repeated verbatim at more than forty call sites, which
// is the same boilerplate the duplication detector reports across this package.
// Keeping them in one place also means a change to how the connection is
// resolved reaches every command rather than the sites someone remembered.
func NewPSCommandOpts(conf *config.ProviderConf) CreatePSCommandOpts {
	return CreatePSCommandOpts{
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: conf.IsPassCredentialsEnabled(),
		Username:        conf.Settings.WinRMUsername,
		Password:        conf.Settings.WinRMPassword,
		Server:          conf.IdentifyDomainController(),
	}
}

// NewDomainPSCommandOpts returns options aimed at the domain rather than at a
// specific domain controller, which is what the Group Policy cmdlets need.
//
// The domain name falls back to `$env:computername` when it equals the Kerberos
// realm, and the command runs through Invoke-Command whenever credentials are
// passed. That resolution was written out at fourteen call sites, all of them
// identical and none of them using the resolved name for anything but the
// Server field.
func NewDomainPSCommandOpts(conf *config.ProviderConf) CreatePSCommandOpts {
	domainName := conf.Settings.DomainName
	if conf.Settings.KrbRealm == domainName {
		domainName = "$env:computername"
	}

	opts := NewPSCommandOpts(conf)
	opts.InvokeCommand = conf.IsPassCredentialsEnabled()
	opts.Server = domainName

	return opts
}

// RunPSCommand builds and runs one or more PowerShell commands and turns both
// failure modes into an error naming what was attempted.
//
// `what` completes the sentence "while …", so it reads as a present participle
// plus the context the caller has: "creating group %q", "removing the OU".
//
// Run reports an error only for transport failures. A command the directory
// refuses comes back with no error and a non-zero exit code, which is the check
// callers used to write out by hand and occasionally forgot.
//
// Callers that treat a particular failure as success — a group that already
// exists, a GPO link that is already gone — match on the returned error, whose
// text carries the command's stderr in both cases. The result is nil whenever
// the error is non-nil.
func RunPSCommand(conf *config.ProviderConf, opts CreatePSCommandOpts, what string, cmds ...string) (*PSCommandResult, error) {
	result, err := NewPSCommand(cmds, opts).Run(conf)
	if cmdErr := checkPSResult(result, err, what, opts.Password); cmdErr != nil {
		return nil, cmdErr
	}
	return result, nil
}

// checkPSResult is the error half of RunPSCommand, split off so it can be
// tested without a WinRM connection.
//
// stderr and stdout of a failed command go into the error, and Terraform prints
// that error to the console and into CI logs. Both can quote the command that
// produced them, which for New-ADUser and Set-ADAccountPassword is a command
// carrying a password, so both go through the same redaction Run applies to its
// debug log.
func checkPSResult(result *PSCommandResult, err error, what, password string) error {
	if err != nil {
		return fmt.Errorf("while %s: %s", what, err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("while %s: exit code %d, stderr: %s, stdout: %s",
			what, result.ExitCode,
			redactSensitiveData(result.StdErr, password),
			redactSensitiveData(result.Stdout, password))
	}
	return nil
}

type PSCommand struct {
	CreatePSCommandOpts
	cmd string
}

func NewPSCommand(cmds []string, opts CreatePSCommandOpts) *PSCommand {
	if opts.InvokeCommand && opts.PassCredentials {
		invokeCmds := []string{"Invoke-Command -Authentication Kerberos"}
		if opts.JSONOutput {
			cmds = append(cmds, "| ConvertTo-Json")
		}

		invokeCmds = append(invokeCmds, fmt.Sprintf("-ScriptBlock {%s}", strings.Join(cmds, " ")))
		cmds = invokeCmds
	}

	if opts.PassCredentials {
		if !opts.SkipCredPrefix {
			cmdUsername := fmt.Sprintf("$User = \"%s\"\n", opts.Username)
			cmdPassword := fmt.Sprintf("$Password = ConvertTo-SecureString -String \"%s\" -AsPlainText -Force\n", opts.Password)
			cmds = append([]string{"$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $Password\n"}, cmds...)
			cmds = append([]string{cmdUsername}, cmds...)
			cmds = append([]string{cmdPassword}, cmds...)
		}
		if !opts.SkipCredSuffix {
			cmds = append(cmds, "-Credential $Credential")
		}
	}

	if opts.PassCredentials && opts.Server != "" {
		switch {
		case opts.InvokeCommand:
			cmds = append(cmds, fmt.Sprintf("-Computername %s", opts.Server))
		default:
			cmds = append(cmds, fmt.Sprintf("-Server %s", opts.Server))
		}
	}

	if !opts.InvokeCommand && opts.JSONOutput {
		cmds = append(cmds, "| ConvertTo-Json")
	}

	cmd := strings.Join(cmds, " ")

	logStr := redactSensitiveData(cmd, opts.Password)
	log.Printf("[DEBUG] Constructing powerrshell command: %s ", logStr)

	res := PSCommand{
		CreatePSCommandOpts: opts,
		cmd:                 cmd,
	}

	return &res
}

// redactSensitiveData redacts passwords and other sensitive data from log output
func redactSensitiveData(cmd string, winrmPassword string) string {
	logStr := cmd

	// Redact WinRM password if PassCredentials is enabled
	if winrmPassword != "" {
		logStr = strings.ReplaceAll(logStr, winrmPassword, "<REDACTED>")
	}

	// Redact passwords in -AccountPassword parameter using regex
	// Matches: -AccountPassword (ConvertTo-SecureString -AsPlainText "password" -Force)
	accountPasswordRegex := regexp.MustCompile(`-AccountPassword\s+\(ConvertTo-SecureString\s+-AsPlainText\s+"[^"]*"\s+-Force\)`)
	logStr = accountPasswordRegex.ReplaceAllString(logStr, "-AccountPassword (ConvertTo-SecureString -AsPlainText \"<REDACTED>\" -Force)")

	// Also handle single-quoted passwords
	accountPasswordRegexSingleQuote := regexp.MustCompile(`-AccountPassword\s+\(ConvertTo-SecureString\s+-AsPlainText\s+'[^']*'\s+-Force\)`)
	logStr = accountPasswordRegexSingleQuote.ReplaceAllString(logStr, "-AccountPassword (ConvertTo-SecureString -AsPlainText '<REDACTED>' -Force)")

	// Redact passwords in -NewPassword parameter (used by Set-ADAccountPassword)
	// Matches: -NewPassword (ConvertTo-SecureString -AsPlainText "password" -Force)
	newPasswordRegex := regexp.MustCompile(`-NewPassword\s+\(ConvertTo-SecureString\s+-AsPlainText\s+"[^"]*"\s+-Force\)`)
	logStr = newPasswordRegex.ReplaceAllString(logStr, "-NewPassword (ConvertTo-SecureString -AsPlainText \"<REDACTED>\" -Force)")

	// Also handle single-quoted passwords for NewPassword
	newPasswordRegexSingleQuote := regexp.MustCompile(`-NewPassword\s+\(ConvertTo-SecureString\s+-AsPlainText\s+'[^']*'\s+-Force\)`)
	logStr = newPasswordRegexSingleQuote.ReplaceAllString(logStr, "-NewPassword (ConvertTo-SecureString -AsPlainText '<REDACTED>' -Force)")

	return logStr
}

// Run will run a powershell command and return the stdout and stderr
// The output is converted to JSON if the json parameter is set to true.
func (p *PSCommand) Run(conf *config.ProviderConf) (*PSCommandResult, error) {
	var (
		stdout string
		stderr string
		res    int
		err    error
	)
	conn, err := conf.AcquireWinRMClient()
	if err != nil {
		return nil, fmt.Errorf("while acquiring winrm client: %s", err)
	}
	defer conf.ReleaseWinRMClient(conn)

	if !p.ExecLocally && conn != nil {
		log.Printf("[DEBUG] Executing command on remote host")
		stdout, stderr, res, err = conn.RunPSWithString(p.cmd, "")
		log.Printf("[DEBUG] Powershell command exited with code %d", res)
	} else {
		log.Printf("[DEBUG] Creating local shell")
		localShell := NewLocalPSSession()
		log.Printf("[DEBUG] Executing command on local host")
		encodedCmd := winrm.Powershell(p.cmd)
		stdout, stderr, res, err = localShell.ExecutePScmd(encodedCmd)
	}

	if err != nil {
		log.Printf("[DEBUG] run error : %s", err)
		return nil, fmt.Errorf("powershell command failed with exit code %d\nstdout: %s\nstderr: %s\nerror: %s",
			res, redactSensitiveData(stdout, p.Password), redactSensitiveData(stderr, p.Password), err)
	}

	log.Printf("[DEBUG] Powershell command exited with code %d", res)
	if res != 0 {
		// Redact sensitive data from stdout/stderr before logging
		redactedStdout := redactSensitiveData(stdout, p.Password)
		redactedStderr := redactSensitiveData(stderr, p.Password)
		log.Printf("[DEBUG] Stdout: %s, Stderr: %s", redactedStdout, redactedStderr)
	}

	// Decode stderr here for the error to be human readable if we need to return early
	stderr, xmlErr := decodeXMLCli(stderr)
	if xmlErr != nil {
		log.Printf("[DEBUG] stderr was not serialised as CLIXML, passing back as is")
	}

	result := &PSCommandResult{
		Stdout:   strings.TrimSpace(stdout),
		StdErr:   stderr,
		ExitCode: res,
	}

	if p.ForceArray && result.Stdout != "" && string(result.Stdout[0]) != "[" {
		result.Stdout = fmt.Sprintf("[%s]", result.Stdout)
	}

	return result, nil
}

func (p *PSCommand) String() string {
	return p.cmd
}

// PSCommandResult holds the stdout, stderr and exit code of a powershell command
type PSCommandResult struct {
	Stdout   string
	StdErr   string
	ExitCode int
}

type psString string

func (s *psString) UnmarshalText(text []byte) error {
	str := string(text)
	str = strings.TrimSpace(str)
	if str[0] == '+' && len(str) > 2 {
		*s = psString(fmt.Sprintf("\n%s", str[2:]))
	} else {
		*s = psString(str)
	}

	return nil
}

// PSOutput is used to unmarshall CLIXML output
// Right now we are only using this to extract error messages, but it can be extended
// to unpack more elements if required.
type PSOutput struct {
	PSStrings []psString `xml:"S"`
}

func (p *PSOutput) stringSlice() []string {
	out := make([]string, len(p.PSStrings))
	for idx, v := range p.PSStrings {
		out[idx] = string(v)
	}
	return out
}

// String() return a string containing the error message that was serialised in a CLIXML message
func (p *PSOutput) String() string {
	str := strings.Join(p.stringSlice(), "")
	replacer := strings.NewReplacer("_x000D_", "", "_x000A_", "")
	str = replacer.Replace(str)
	return str
}

func decodeXMLCli(xmlDoc string) (string, error) {
	// If stderr is formatted in CLIXML try to extract the error message
	if strings.Contains(xmlDoc, "#< CLIXML") {
		xmlDoc = strings.Replace(xmlDoc, "#< CLIXML", "", -1)
		var v PSOutput
		err := xml.Unmarshal([]byte(xmlDoc), &v)
		if err != nil {
			return "", fmt.Errorf("while unmarshalling CLIXML document: %s", err)
		}
		xmlDoc = strings.TrimSpace(v.String())
	}
	return xmlDoc, nil
}
