package winrmhelper

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// hostileRaw is the value every text field receives below. It holds each
// character class that broke a command before: an ASCII double quote, a
// backslash (doubled by %q, and part of every escaped DN), a subexpression,
// the typographic double quotes, and a backtick.
const hostileRaw = "x\"y\\z$(w)\u201cq\u201d`end"

// hostileQuoted is hostileRaw as a PowerShell double-quoted literal, written
// out by hand so that the tests do not compare psQuote with itself. The
// parser test further down checks that PowerShell reads it back as hostileRaw.
const hostileQuoted = "\"x`\"y\\z`$(w)`\u201cq`\u201d``end\""

func TestPSQuote(t *testing.T) {
	if got := psQuote(hostileRaw); got != hostileQuoted {
		t.Errorf("psQuote(%q)\n got: %s\nwant: %s", hostileRaw, got, hostileQuoted)
	}
	if got := psQuoteSanitised(SanitiseString(hostileRaw)); got != hostileQuoted {
		t.Errorf("psQuoteSanitised(SanitiseString(%q))\n got: %s\nwant: %s", hostileRaw, got, hostileQuoted)
	}
	// U+001F used to become `e, which PowerShell reads as ESC.
	if got, want := psQuote("unit\x1fsep"), "\"unit\x1fsep\""; got != want {
		t.Errorf("psQuote of U+001F = %q, want %q", got, want)
	}
}

func sanitisedHostile() string { return SanitiseString(hostileRaw) }

// wantParams fails for every parameter that does not carry hostileQuoted.
func wantParams(t *testing.T, cmd string, params ...string) {
	t.Helper()
	for _, p := range params {
		if needle := "-" + p + " " + hostileQuoted; !strings.Contains(cmd, needle) {
			t.Errorf("-%s does not carry the value quoted once\ncommand: %s\n   want: %s", p, cmd, needle)
		}
	}
}

// userTextParams are the New-ADUser parameters newUserCommand fills from a
// text field, in the order the function renders them.
var userTextParams = []string{
	"Name", "SamAccountName", "UserPrincipalName", "DisplayName", "Path", "City", "Company",
	"Department", "Description", "Division", "EmailAddress", "EmployeeID", "EmployeeNumber", "Fax",
	"GivenName", "HomeDirectory", "HomeDrive", "HomePhone", "HomePage", "Initials", "MobilePhone",
	"Office", "OfficePhone", "Organization", "OtherName", "POBox", "PostalCode", "State",
	"StreetAddress", "Surname", "Title",
}

func hostileUser() *User {
	h := sanitisedHostile()
	return &User{
		Username: h, SAMAccountName: h, PrincipalName: h, DisplayName: h, Container: h, City: h,
		Company: h, Department: h, Description: h, Division: h, EmailAddress: h, EmployeeID: h,
		EmployeeNumber: h, Fax: h, GivenName: h, HomeDirectory: h, HomeDrive: h, HomePhone: h,
		HomePage: h, Initials: h, MobilePhone: h, Office: h, OfficePhone: h, Organization: h,
		OtherName: h, POBox: h, PostalCode: h, State: h, StreetAddress: h, Surname: h, Title: h,
		Password: h,
	}
}

func TestNewUserCommandQuotesEveryFieldOnce(t *testing.T) {
	cmd, err := newUserCommand(hostileUser())
	if err != nil {
		t.Fatal(err)
	}
	wantParams(t, cmd, userTextParams...)
	if needle := "-AsPlainText " + hostileQuoted + " -Force"; !strings.Contains(cmd, needle) {
		t.Errorf("the password is not quoted once\ncommand: %s", cmd)
	}

	// The country code is upper-cased, so it gets a plain value of its own.
	cmd, err = newUserCommand(&User{Username: "u", Country: "de"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, `-Country "DE"`) {
		t.Errorf("the country is not rendered upper-cased and quoted once\ncommand: %s", cmd)
	}
}

func TestNewGroupCommandQuotesEveryFieldOnce(t *testing.T) {
	h := sanitisedHostile()
	cmd := newGroupCommand(&Group{Name: h, Scope: h, Category: h, Container: h, SAMAccountName: h, Description: h})
	wantParams(t, cmd, "Name", "GroupScope", "GroupCategory", "Path", "SamAccountName", "Description")
}

func TestNewOrgUnitCommandQuotesEveryFieldOnce(t *testing.T) {
	h := sanitisedHostile()
	cmd := newOrgUnitCommand(&OrgUnit{Name: h, Description: h, Path: h})
	wantParams(t, cmd, "Name", "Description", "Path")
}

func TestNewComputerCommandQuotesEveryFieldOnce(t *testing.T) {
	h := sanitisedHostile()
	cmd := newComputerCommand(&Computer{Name: h, SAMAccountName: h, Path: h, Description: h})
	wantParams(t, cmd, "Name", "SamAccountName", "Path", "Description")
}

func TestNewGPOCommandQuotesEveryFieldOnce(t *testing.T) {
	h := sanitisedHostile()
	cmd := newGPOCommand(&GPO{Name: h, Domain: h, Description: h})
	wantParams(t, cmd, "Name", "Domain", "Comment")
	wantParams(t, getGPOCmdByName(h), "Name")
}

// The rename, move and lookup builders take raw values and must escape them:
// their callers pass d.Get results and change maps.
func TestRawValueBuildersEscape(t *testing.T) {
	wantParams(t, renameObjectCommand(upperGUID, hostileRaw), "NewName")
	wantParams(t, moveObjectCommand(upperGUID, hostileRaw), "TargetPath")
	user, password := credentialAssignments(hostileRaw, hostileRaw)
	if want := "$User = " + hostileQuoted + "\n"; user != want {
		t.Errorf("credential user line\n got: %q\nwant: %q", user, want)
	}
	if want := "-String " + hostileQuoted + " "; !strings.Contains(password, want) {
		t.Errorf("credential password line %q does not contain %q", password, want)
	}
}

// The update, lookup and file builders, which the create tests above do not
// reach. Builders that take sanitised values get h, the others the raw value.
func TestUpdateAndLookupBuildersQuoteOnce(t *testing.T) {
	h := sanitisedHostile()

	cmd, ok := orgUnitLookupCommand(h, "", "")
	if !ok {
		t.Fatal("lookup by identity reported incomplete input")
	}
	wantParams(t, cmd, "Identity")
	cmd, ok = orgUnitLookupCommand("", h, h)
	if !ok {
		t.Fatal("lookup by name and path reported incomplete input")
	}
	wantParams(t, cmd, "Name", "Path")
	if _, ok := orgUnitLookupCommand("", h, ""); ok {
		t.Error("lookup by name without a path must report incomplete input")
	}
	wantParams(t, orgUnitLookupCommandByDN(h), "Identity")
	wantParams(t, setOrgUnitCommand(h, map[string]any{"description": hostileRaw, "display_name": hostileRaw, "path": "ignored"}),
		"Identity", "Description", "DisplayName")

	wantParams(t, computerLookupCommand(h), "Identity")
	wantParams(t, setComputerDescriptionCommand(upperGUID, hostileRaw), "Description")
	if got := setComputerDescriptionCommand(upperGUID, ""); !strings.HasSuffix(got, " -Description $null") {
		t.Errorf("an empty description must clear the attribute with $null: %s", got)
	}

	wantParams(t, renameGPOCommand(&GPO{ID: upperGUID, Domain: h}, h), "TargetName", "Domain")
	wantParams(t, removeGPOCommand(&GPO{Name: h, Domain: h}), "Name", "Domain")
	if got := gpoStatusCommand(upperGUID, h); !strings.HasSuffix(got, ".GpoStatus = "+hostileQuoted) {
		t.Errorf("the GPO status is not quoted once: %s", got)
	}

	link := &GPLink{GPOGuid: upperGUID, Target: h, Enabled: true}
	wantParams(t, newGPLinkCommand(link), "Target")
	wantParams(t, removeGPLinkCommand(link), "Target")
	cmd, ok = setGPLinkCommand(link, map[string]any{"enforced": true})
	if !ok {
		t.Fatal("a change of enforced produced no Set-GPLink call")
	}
	wantParams(t, strings.Replace(cmd, "-target", "-Target", 1), "Target")
	if _, ok := setGPLinkCommand(link, map[string]any{"target_dn": "x"}); ok {
		t.Error("a change Set-GPLink cannot apply must produce no call")
	}

	for name, got := range map[string]string{"Get-Content": getContentCommand(hostileRaw), "Remove-Item": removeItemCommand(hostileRaw)} {
		if !strings.HasSuffix(got, " "+hostileQuoted) {
			t.Errorf("%s does not quote the path once: %s", name, got)
		}
	}
	mkdir, copyAndRemove := sysvolCopyCommands(hostileRaw, hostileRaw, hostileRaw)
	if n := strings.Count(mkdir, hostileQuoted); n != 2 {
		t.Errorf("the mkdir command quotes the directory %d times, want 2: %s", n, mkdir)
	}
	if n := strings.Count(copyAndRemove, hostileQuoted); n != 3 {
		t.Errorf("the copy command quotes its paths %d times, want 3: %s", n, copyAndRemove)
	}
	wantParams(t, machineExtensionNamesCommand(hostileRaw, hostileRaw), "Identity")
	if got := machineExtensionNamesCommand(hostileRaw, hostileRaw); !strings.Contains(got, "gPCMachineExtensionNames="+hostileQuoted+"}") {
		t.Errorf("the extension names are not quoted once: %s", got)
	}
}

func TestResetPasswordCommandQuotesOnce(t *testing.T) {
	cmd := resetPasswordCommand(upperGUID, sanitisedHostile())
	if needle := "-AsPlainText " + hostileQuoted + " -Force"; !strings.Contains(cmd, needle) {
		t.Errorf("the password is not quoted once\ncommand: %s", cmd)
	}
}

// The credential preamble embeds the WinRM password escaped, so the log must
// lose the escaped form as well as the raw one.
func TestWinRMPasswordIsRedactedInItsEscapedForm(t *testing.T) {
	const raw = "Pa$$w\"rd"
	_, line := credentialAssignments("admin", raw)
	got := redactSensitiveData(line, raw)
	if strings.Contains(got, SanitiseString(raw)) || strings.Contains(got, "w`\"rd") {
		t.Errorf("the escaped WinRM password survived redaction: %s", got)
	}
	if !strings.Contains(got, "<REDACTED>") {
		t.Errorf("nothing was redacted: %s", got)
	}
}

// psRoundTrip is one rendered command and the raw value each named parameter
// must reach the cmdlet with.
type psRoundTrip struct {
	Name    string            `json:"name"`
	Command string            `json:"command"`
	Want    map[string]string `json:"want"`
}

func roundTripCases(t *testing.T) []psRoundTrip {
	t.Helper()
	h := sanitisedHostile()
	all := func(params ...string) map[string]string {
		m := map[string]string{}
		for _, p := range params {
			m[p] = hostileRaw
		}
		return m
	}
	userCmd, err := newUserCommand(hostileUser())
	if err != nil {
		t.Fatal(err)
	}
	userWant := all(userTextParams...)
	userWant["AccountPassword"] = hostileRaw
	user, password := credentialAssignments(hostileRaw, hostileRaw)
	return []psRoundTrip{
		{"New-ADUser", userCmd, userWant},
		{"Set-ADAccountPassword", resetPasswordCommand(upperGUID, h), map[string]string{"Identity": upperGUID, "NewPassword": hostileRaw}},
		{"Rename-ADObject", renameObjectCommand(upperGUID, hostileRaw), map[string]string{"Identity": upperGUID, "NewName": hostileRaw}},
		{"Move-ADObject", moveObjectCommand(upperGUID, hostileRaw), map[string]string{"Identity": upperGUID, "TargetPath": hostileRaw}},
		{"Move-ADObject with an escaped DN", moveObjectCommand(upperGUID, `OU=Doe\, Jane,DC=example,DC=com`), map[string]string{"TargetPath": `OU=Doe\, Jane,DC=example,DC=com`}},
		{"New-ADGroup", newGroupCommand(&Group{Name: h, Scope: h, Category: h, Container: h, SAMAccountName: h, Description: h}),
			all("Name", "GroupScope", "GroupCategory", "Path", "SamAccountName", "Description")},
		{"New-ADOrganizationalUnit", newOrgUnitCommand(&OrgUnit{Name: h, Description: h, Path: h}), all("Name", "Description", "Path")},
		{"New-ADComputer", newComputerCommand(&Computer{Name: h, SAMAccountName: h, Path: h, Description: h}), all("Name", "SamAccountName", "Path", "Description")},
		{"New-GPO", newGPOCommand(&GPO{Name: h, Domain: h, Description: h}), all("Name", "Domain", "Comment")},
		{"Get-GPO", getGPOCmdByName(h), all("Name")},
		{"credentials", user + password + "Probe-Credential -User $User -Password $Password", all("User", "Password")},
		{"hashtable key", "Probe-Hashtable -Table @{" + PSHashtableEntry("a$b'c\u2019d", GetString(hostileRaw)) + "}",
			map[string]string{"Table.key": "a$b'c\u2019d", "Table.value": hostileRaw}},
		{"Get-ADObject by identity", orgUnitLookupCommandByDN(h), map[string]string{"Identity": hostileRaw}},
		{"Get-ADObject by name", mustLookup(t, "", h, h), all("Name", "Path")},
		{"Set-ADOrganizationalUnit", setOrgUnitCommand(h, map[string]any{"description": hostileRaw, "display_name": hostileRaw}),
			all("Identity", "Description", "DisplayName")},
		{"Get-ADComputer", computerLookupCommand(h), all("Identity")},
		{"Set-ADComputer", setComputerDescriptionCommand(upperGUID, hostileRaw), all("Description")},
		{"Rename-GPO", renameGPOCommand(&GPO{ID: upperGUID, Domain: h}, h), all("TargetName", "Domain")},
		{"Remove-GPO", removeGPOCommand(&GPO{Name: h, Domain: h}), all("Name", "Domain")},
		{"New-GPLink", newGPLinkCommand(&GPLink{GPOGuid: upperGUID, Target: h}), all("Target")},
		{"Remove-GPlink", removeGPLinkCommand(&GPLink{GPOGuid: upperGUID, Target: h}), all("Target")},
		{"Set-GPLink", mustSetGPLink(t, &GPLink{GPOGuid: upperGUID, Target: h}), all("target")},
		{"Get-Content", getContentCommand(hostileRaw), all("_0")},
		{"Remove-Item", removeItemCommand(hostileRaw), all("_0")},
		{"Set-ADObject", machineExtensionNamesCommand(hostileRaw, hostileRaw),
			map[string]string{"Identity": hostileRaw, "Replace.key": "gPCMachineExtensionNames", "Replace.value": hostileRaw}},
	}
}

func mustLookup(t *testing.T, identity, name, path string) string {
	t.Helper()
	cmd, ok := orgUnitLookupCommand(identity, name, path)
	if !ok {
		t.Fatal("orgUnitLookupCommand reported incomplete input")
	}
	return cmd
}

func mustSetGPLink(t *testing.T, g *GPLink) string {
	t.Helper()
	cmd, ok := setGPLinkCommand(g, map[string]any{"enabled": true})
	if !ok {
		t.Fatal("setGPLinkCommand produced no call")
	}
	return cmd
}

// psProbeScript replaces every cmdlet the cases call with a stub that records
// the value of each named parameter, then runs each command with the real
// parser. ConvertTo-SecureString hands back its plain text, so a password
// parameter records the text the account would get.
const psProbeScript = `
$ErrorActionPreference = 'Stop'
function Record {
  param([string]$Cmdlet, [object[]]$A)
  $values = @{}
  $pos = 0
  for ($i = 0; $i -lt $A.Count; $i++) {
    $tok = [string]$A[$i]
    if ($tok.StartsWith('-') -and $i + 1 -lt $A.Count) {
      $v = $A[$i + 1]
      # A switch such as -Passthru is followed by the next parameter name.
      if ($v -is [string] -and $v.StartsWith('-')) { continue }
      $name = $tok.TrimStart('-').TrimEnd(':')
      if ($v -is [hashtable]) {
        $k = @($v.Keys)[0]
        $values[$name + '.key'] = [string]$k
        $values[$name + '.value'] = [string]$v[$k]
      } else {
        $values[$name] = [string]$v
      }
      $i++
    } elseif (-not $tok.StartsWith('-')) {
      $values['_' + $pos] = $tok
      $pos++
    }
  }
  $script:got = $values
}
# Read the cases before the stubs replace Get-Content.
$cases = Get-Content -Raw -LiteralPath $args[0] | ConvertFrom-Json
function ConvertTo-SecureString { foreach ($a in $args) { if (-not ([string]$a).StartsWith('-')) { return [string]$a } } }
foreach ($c in 'New-ADUser','Set-ADAccountPassword','Rename-ADObject','Move-ADObject','New-ADGroup',
                'New-ADOrganizationalUnit','New-ADComputer','New-GPO','Get-GPO','Probe-Credential','Probe-Hashtable',
                'Get-ADObject','Set-ADOrganizationalUnit','Get-ADComputer','Set-ADComputer','Rename-GPO','Remove-GPO',
                'New-GPLink','Remove-GPlink','Set-GPLink','Get-Content','Remove-Item','Set-ADObject') {
  Set-Item -Path ("function:global:" + $c) -Value ([scriptblock]::Create("Record '$c' ` + "`" + `$args"))
}
$out = @()
foreach ($case in $cases) {
  $script:got = $null
  try { Invoke-Expression $case.command; $err = '' } catch { $err = $_.Exception.Message }
  $out += @{ name = $case.name; got = $script:got; error = $err }
}
$out | ConvertTo-Json -Depth 5 -Compress
`

// TestPowerShellParsesEveryCommandBackToTheRawValues is the measurement the
// text tests above rest on: it runs every rendered command through the real
// PowerShell parser. GitHub's ubuntu runners ship pwsh, so CI fails rather than
// skips when it is missing.
func TestPowerShellParsesEveryCommandBackToTheRawValues(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("pwsh is not on PATH in CI; this test is the only check that PowerShell reads the commands as intended")
		}
		t.Skip("pwsh is not on PATH")
	}

	cases := roundTripCases(t)
	dir := t.TempDir()
	casesPath := filepath.Join(dir, "cases.json")
	scriptPath := filepath.Join(dir, "probe.ps1")
	raw, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(casesPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scriptPath, []byte(psProbeScript), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File", scriptPath, casesPath).CombinedOutput()
	if err != nil {
		t.Fatalf("pwsh failed: %v\n%s", err, out)
	}
	var results []struct {
		Name  string            `json:"name"`
		Got   map[string]string `json:"got"`
		Error string            `json:"error"`
	}
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("pwsh output is not the expected JSON: %v\n%s", err, out)
	}
	if len(results) != len(cases) {
		t.Fatalf("pwsh reported %d results for %d cases\n%s", len(results), len(cases), out)
	}
	for i, c := range cases {
		r := results[i]
		if r.Error != "" {
			t.Errorf("%s: PowerShell rejected the command: %s\ncommand: %s", c.Name, r.Error, c.Command)
			continue
		}
		for param, want := range c.Want {
			if got, ok := r.Got[param]; !ok || got != want {
				t.Errorf("%s: -%s reached the cmdlet as %s, want %s", c.Name, param, strconv.Quote(got), strconv.Quote(want))
			}
		}
	}
}

// quoteVerbAllowed matches the arguments that may still be formatted with %q:
// GUIDs, which are hexadecimal, and the Yes/No constants of a GPO link.
var quoteVerbAllowed = regexp.MustCompile(`(?i)(guid|\.id|yesno|enabled|enforced)$`)

// commandQuotingViolations reports every fmt.Sprintf in src that puts a value
// into a PowerShell command with %q, unless the value is allowed above, or
// that wraps a %s in literal double quotes. Sprintf calls that render the
// "what" description of RunPSCommand are prose, not PowerShell, and skipped.
func commandQuotingViolations(fset *token.FileSet, file *ast.File) []string {
	var found []string
	skip := map[*ast.CallExpr]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if what := runPSCommandWhat(call); what != nil {
			skip[what] = true
		}
		if format, ok := sprintfFormat(call); ok && !skip[call] {
			found = append(found, formatViolations(fset, call, format)...)
		}
		return true
	})
	return found
}

// runPSCommandWhat returns the Sprintf call that renders the "what" argument
// of a RunPSCommand call, or nil.
func runPSCommandWhat(call *ast.CallExpr) *ast.CallExpr {
	id, ok := call.Fun.(*ast.Ident)
	if !ok || id.Name != "RunPSCommand" || len(call.Args) < 2 {
		return nil
	}
	what, _ := call.Args[1].(*ast.CallExpr)
	return what
}

// sprintfFormat returns the literal format string of a fmt.Sprintf call.
func sprintfFormat(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Sprintf" || len(call.Args) == 0 {
		return "", false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok {
		return "", false
	}
	format, err := strconv.Unquote(lit.Value)
	return format, err == nil
}

// formatViolations checks one Sprintf call against the two rules.
func formatViolations(fset *token.FileSet, call *ast.CallExpr, format string) []string {
	var found []string
	pos := fset.Position(call.Pos()).String()
	if strings.Contains(format, `"%s"`) {
		found = append(found, pos+`: "%s" wraps a value in quotes without escaping it; use psQuote or psQuoteSanitised`)
	}
	for _, argIndex := range quoteVerbArgs(format) {
		if argIndex >= len(call.Args) {
			continue
		}
		if text := exprSource(fset, call.Args[argIndex]); !quoteVerbAllowed.MatchString(text) {
			found = append(found, pos+": %q formats "+text+"; use psQuote or psQuoteSanitised")
		}
	}
	return found
}

// quoteVerbArgs returns the call-argument index of every %q verb in format.
// Argument 0 is the format itself, so the first verb maps to index 1.
func quoteVerbArgs(format string) []int {
	var out []int
	verb := 0
	for i := 0; i+1 < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		i++
		if format[i] == '%' {
			continue
		}
		verb++
		if format[i] == 'q' {
			out = append(out, verb)
		}
	}
	return out
}

func exprSource(fset *token.FileSet, e ast.Expr) string {
	start, end := fset.Position(e.Pos()).Offset, fset.Position(e.End()).Offset
	src, err := os.ReadFile(fset.Position(e.Pos()).Filename)
	if err != nil || end > len(src) {
		return "?"
	}
	return string(src[start:end])
}

// TestNoCommandQuotesAValueWithGoRules keeps the quoting in one place: every
// non-test file of this package is read, and a %q or a bare "%s" around a value
// in a command fails the test.
func TestNoCommandQuotesAValueWithGoRules(t *testing.T) {
	// Positive control: the checker must flag the shape this change removed.
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.go")
	if err := os.WriteFile(bad, []byte("package x\nimport \"fmt\"\nvar _ = fmt.Sprintf(\"New-ADUser -Name %q\", u.Name)\nvar _ = fmt.Sprintf(`Get-Content \"%s\"`, p)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, bad, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := commandQuotingViolations(fset, f); len(got) != 2 {
		t.Fatalf("the checker found %d of the 2 planted violations: %v", len(got), got)
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		checked++
		for _, v := range commandQuotingViolations(fset, f) {
			t.Error(v)
		}
	}
	if checked == 0 {
		t.Fatal("no source file was checked")
	}
}
