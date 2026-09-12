package winrmhelper

import (
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
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

	// Secrets are the exact substrings a caller embedded in the command and
	// that must never be rendered. See the Secret option.
	Secrets []string
}

// A PSOption changes one aspect of how a command is built. Everything that
// follows from the provider connection is filled in by NewPSCommandOpts, so a
// call site names only what makes it different from an ordinary command.
type PSOption func(*config.ProviderConf, *CreatePSCommandOpts)

// JSONOutput pipes the command through ConvertTo-Json. Use it where the caller
// parses stdout as a JSON document, and nowhere else: the append is wasted on a
// command whose output nobody reads, and it destroys the output of one that
// returns plain text, such as Get-Content or a path.
func JSONOutput() PSOption {
	return func(_ *config.ProviderConf, o *CreatePSCommandOpts) { o.JSONOutput = true }
}

// ForceArray wraps a single JSON object in brackets, so a caller unmarshalling
// into a slice gets one element rather than a type error.
func ForceArray() PSOption {
	return func(_ *config.ProviderConf, o *CreatePSCommandOpts) { o.ForceArray = true }
}

// Domain aims the command at the domain rather than at a specific domain
// controller, which is what the Group Policy cmdlets need.
//
// The domain name falls back to `$env:computername` when it equals the Kerberos
// realm, and the command runs through Invoke-Command whenever credentials are
// passed.
func Domain() PSOption {
	return func(conf *config.ProviderConf, o *CreatePSCommandOpts) {
		domainName := conf.Settings.DomainName
		if conf.Settings.KrbRealm == domainName {
			domainName = "$env:computername"
		}
		o.InvokeCommand = conf.IsPassCredentialsEnabled()
		o.Server = domainName
	}
}

// ComposedCommand marks a command assembled from sub-commands that each already
// carry their own `-Credential` and `-Server`.
//
// The two switches travel together for one reason: the wrapper still has to
// emit the `$Credential` preamble once at the top, but appending `-Credential`
// or `-Server` again would apply them to the last cmdlet of the pipeline rather
// than to the whole. Build the sub-commands with SkipCredentialPreamble.
func ComposedCommand() PSOption {
	return func(_ *config.ProviderConf, o *CreatePSCommandOpts) {
		o.Server = ""
		o.SkipCredSuffix = true
	}
}

// SecretPassword registers a password so that the text it renders to in the
// command is redacted out of every error and log.
//
// It takes the password rather than the rendered text on purpose. The caller
// embeds strconv.Quote(password), and the rule for what to register from that is
// not obvious twice in a row: strconv.Quote("") is the two-character string `""`,
// so registering it unconditionally redacts every empty string literal the
// provider renders — an attribute set to "", a JSON field, the lot. Keeping the
// rendering and that exception in one place means a call site cannot get it
// wrong, and one test covers both sites.
//
// This exists because the pattern-based redaction further down cannot be made
// reliable: it anchors on `-AsPlainText "…" -Force)`, and a password containing a
// double quote renders with an escaped quote inside that anchor, which the
// pattern does not match at all — the full password then reaches the Terraform
// console. A literal replacement is insensitive to quoting and escaping.
//
// Two gaps remain, both measured rather than assumed, and both in the same
// place: the `+`-prefixed position message, where PowerShell echoes the command
// back. A literal cannot match there once the text has been transformed —
// truncated inside the secret, or reassembled from CLIXML fragments, where
// psString.UnmarshalText trims each fragment and so inserts or deletes a space
// inside the value. A sweep of console widths 60-220 over the two commands that
// carry a password leaks at 31 and 24 widths respectively; 80 and 120 are not
// among them for those exact shapes, which is luck rather than a defence.
//
// Redaction cannot close either — the text arrives already transformed. What
// would is not emitting the echo: dropping the `+` lines during decoding, or
// asking the host for a view that omits them. That changes what an operator sees
// in an error, so it is a decision, not a fix to slip into this commit.
func SecretPassword(password string) PSOption {
	return func(_ *config.ProviderConf, o *CreatePSCommandOpts) {
		if password == "" {
			return
		}
		o.Secrets = append(o.Secrets, strconv.Quote(password))
	}
}

// SkipCredentialPreamble leaves out the `$User`/`$Password`/`$Credential` lines,
// for a sub-command that will be embedded in a larger command which emits them.
func SkipCredentialPreamble() PSOption {
	return func(_ *config.ProviderConf, o *CreatePSCommandOpts) { o.SkipCredPrefix = true }
}

// WithoutCredentials runs the command as the connected user. Nothing is added to
// it — the credential preamble, the `-Credential` suffix and the `-Server`
// argument are all conditional on credentials being passed.
func WithoutCredentials() PSOption {
	return func(_ *config.ProviderConf, o *CreatePSCommandOpts) { o.PassCredentials = false }
}

// NewPSCommandOpts returns the options for a command against this provider
// connection, with the given options applied.
//
// The five connection-derived fields were repeated verbatim at more than forty
// call sites. Keeping them here means a change to how the connection is
// resolved reaches every command rather than the sites someone remembered.
func NewPSCommandOpts(conf *config.ProviderConf, opts ...PSOption) CreatePSCommandOpts {
	res := CreatePSCommandOpts{
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: conf.IsPassCredentialsEnabled(),
		Username:        conf.Settings.WinRMUsername,
		Password:        conf.Settings.WinRMPassword,
		Server:          conf.IdentifyDomainController(),
	}
	for _, opt := range opts {
		opt(conf, &res)
	}
	return res
}

// RunPSCommand builds and runs a PowerShell command and turns both failure
// modes into an error naming what was attempted.
//
// Everything the command needs beyond `cmd` comes from conf; a call site adds
// an option only where it differs from an ordinary command, which for most of
// them is not at all.
//
// `what` completes the sentence "while …", so it reads as a present participle
// plus the context the caller has: "creating group %q", "removing the OU".
//
// Run reports an error only for transport failures. A command the directory
// refuses comes back with no error and a non-zero exit code, which is the check
// callers used to write out by hand and occasionally forgot.
//
// Callers that treat a particular failure as success — a group that already
// exists, a GPO link that is already gone — ask ErrorMentions, never
// strings.Contains on the error text. The result is nil whenever the error is
// non-nil.
func RunPSCommand(conf *config.ProviderConf, what, cmd string, opts ...PSOption) (*PSCommandResult, error) {
	psOpts := NewPSCommandOpts(conf, opts...)
	result, err := NewPSCommand([]string{cmd}, psOpts).Run(conf)
	if cmdErr := checkPSResult(result, err, what, psOpts.Password, psOpts.Secrets...); cmdErr != nil {
		return nil, cmdErr
	}
	return result, nil
}

// checkPSResult is the error half of RunPSCommand, split off so it can be
// tested without a WinRM connection.
func checkPSResult(result *PSCommandResult, err error, what, password string, secrets ...string) error {
	if err == nil && (result == nil || result.ExitCode == 0) {
		return nil
	}
	return &psError{what: what, result: result, err: err, password: password, secrets: secrets}
}

// psError is what a failed command returns.
//
// It keeps the two readers of a failure apart, because they need opposite
// things. Error() renders the text a person sees: Terraform prints it to the
// console and into CI logs, and a PowerShell error record can quote the command
// that produced it — which for New-ADUser and Set-ADAccountPassword is a command
// carrying a password. So the rendering is redacted.
//
// A caller asking "did the directory say the object was already gone" must read
// the streams UNREDACTED. Redaction is a literal replacement of the WinRM
// password, and a password that happens to contain "Not", "Data", "Item" or
// "Link" rewrites the middle of ADIdentityNotFoundException, GpoLinkNotFound or
// InvalidData. Matching on the rendered text would then fail to recognise an
// object that is gone, and the destroy would fail on every retry.
type psError struct {
	what     string
	result   *PSCommandResult // the raw streams; nil only if Run returned nothing
	err      error            // set when the command could not be run at all
	password string
	secrets  []string
}

func (e *psError) Error() string {
	var stderr, stdout string
	var exitCode int
	if e.result != nil {
		stderr = redactSensitiveData(e.result.StdErr, e.password, e.secrets...)
		stdout = redactSensitiveData(e.result.Stdout, e.password, e.secrets...)
		exitCode = e.result.ExitCode
	}
	if e.err != nil {
		msg := fmt.Sprintf("while %s: %s", e.what, redactSensitiveData(e.err.Error(), e.password, e.secrets...))
		if stderr == "" && stdout == "" {
			// The command did not run; an exit code and two empty streams would
			// say nothing but would read as if it had.
			return msg
		}
		return fmt.Sprintf("%s (exit code %d, stderr: %s, stdout: %s)", msg, exitCode, stderr, stdout)
	}
	return fmt.Sprintf("while %s: exit code %d, stderr: %s, stdout: %s",
		e.what, exitCode, stderr, stdout)
}

// mentions reports whether the command's raw output, or the transport failure,
// contains marker.
func (e *psError) mentions(marker string) bool {
	if marker == "" {
		return false
	}
	if e.result != nil &&
		(strings.Contains(e.result.StdErr, marker) || strings.Contains(e.result.Stdout, marker)) {
		return true
	}
	return e.err != nil && strings.Contains(e.err.Error(), marker)
}

// ErrorMentions reports whether a failed command said any of markers.
//
// Use this instead of strings.Contains(err.Error(), …): the rendered error is
// redacted, and redaction can delete the middle of a marker — see psError. For
// an error that did not come from a command, the text is all there is, so that
// is what gets matched.
func ErrorMentions(err error, markers ...string) bool {
	if err == nil {
		return false
	}
	var cmdErr *psError
	if errors.As(err, &cmdErr) {
		for _, marker := range markers {
			if cmdErr.mentions(marker) {
				return true
			}
		}
		return false
	}
	for _, marker := range markers {
		if marker != "" && strings.Contains(err.Error(), marker) {
			return true
		}
	}
	return false
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

	logStr := redactSensitiveData(cmd, opts.Password, opts.Secrets...)
	log.Printf("[DEBUG] Constructing powerrshell command: %s ", logStr)

	res := PSCommand{
		CreatePSCommandOpts: opts,
		cmd:                 cmd,
	}

	return &res
}

// redactSensitiveData redacts passwords and other sensitive data from log output.
//
// `secrets` are exact substrings a caller registered with the Secret option and
// are replaced literally, which is the only reliable way: the patterns below
// anchor on the shape of the rendered command and miss it entirely when a
// password contains a double quote, or when PowerShell truncated the line.
func redactSensitiveData(cmd string, winrmPassword string, secrets ...string) string {
	logStr := cmd

	for _, secret := range secrets {
		if secret != "" {
			logStr = strings.ReplaceAll(logStr, secret, "<REDACTED>")
		}
	}

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

	log.Printf("[DEBUG] Powershell command exited with code %d", res)

	// Decode stderr here for the error to be human readable if we need to return early
	stderr, xmlErr := decodeXMLCli(stderr)
	if xmlErr != nil {
		log.Printf("[DEBUG] stderr was not serialised as CLIXML, passing back as is")
	}

	if res != 0 {
		// Logged AFTER decoding, not before. A registered secret is the text as
		// it stands in the command; CLIXML carries it XML-encoded, so a password
		// containing & appears as &amp; and no literal replacement matches it.
		// Redacting the encoded form put the full password in the provider log.
		redactedStdout := redactSensitiveData(stdout, p.Password, p.Secrets...)
		redactedStderr := redactSensitiveData(stderr, p.Password, p.Secrets...)
		log.Printf("[DEBUG] Stdout: %s, Stderr: %s", redactedStdout, redactedStderr)
	}

	result := &PSCommandResult{
		Stdout:   strings.TrimSpace(stdout),
		StdErr:   stderr,
		ExitCode: res,
	}

	if err != nil {
		// The streams go back with the error rather than into a message here.
		// checkPSResult is the only place that renders a failure, because a
		// rendered failure is redacted and the markers callers match on have to
		// be read before that happens.
		log.Printf("[DEBUG] run error : %s", redactSensitiveData(err.Error(), p.Password, p.Secrets...))
		return result, err
	}

	if p.ForceArray {
		result.Stdout = bracketLoneObject(result.Stdout)
	}

	return result, nil
}

// bracketLoneObject wraps a single JSON object in brackets.
//
// ConvertTo-Json emits a bare object for one result and an array for several, so
// a caller unmarshalling into a slice gets a type error exactly when the
// directory returns one member. Get-ADGroupMember is the case that hits it.
//
// Split out of Run because Run needs a WinRM connection and this does not.
func bracketLoneObject(stdout string) string {
	if stdout == "" || strings.HasPrefix(stdout, "[") {
		return stdout
	}
	return fmt.Sprintf("[%s]", stdout)
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
	// The length check has to come first: an empty <S></S> element, or one
	// holding only whitespace, leaves str empty and str[0] panics with an index
	// out of range — taking the provider down while decoding an error message.
	if len(str) > 2 && str[0] == '+' {
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
			// The caller logs "passing back as is" and assigns the result, so
			// returning the empty string here discarded the stream instead of
			// preserving it. A marker in a truncated CLIXML document went with
			// it, and the destroy that depends on that marker then failed.
			return xmlDoc, fmt.Errorf("while unmarshalling CLIXML document: %s", err)
		}
		xmlDoc = strings.TrimSpace(v.String())
	}
	return xmlDoc, nil
}
