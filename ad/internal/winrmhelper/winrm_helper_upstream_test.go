package winrmhelper

import (
	"strings"
	"testing"
)

// TestGetStringFormatsNumbersPlainly guards the formatting of numeric custom
// attributes. Active Directory stores what the provider sends verbatim, so
// scientific notation lands in the directory as the literal text "1E+06".
func TestGetStringFormatsNumbersPlainly(t *testing.T) {
	for _, c := range []struct {
		name  string
		input any
		want  string
	}{
		{"large float", float64(1000000), `"1000000"`},
		{"small float", float64(0.5), `"0.5"`},
		{"employee number as float", float64(4711), `"4711"`},
		{"negative", float64(-42), `"-42"`},
		{"int64", int64(1000000), `"1000000"`},
		{"bool", true, `"true"`},
		{"string is sanitised", "a$b", "\"a`$b\""},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := GetString(c.input)
			if got != c.want {
				t.Errorf("GetString(%v) = %s, want %s", c.input, got, c.want)
			}
			if strings.ContainsAny(got, "eE+") && c.name != "bool" {
				t.Errorf("GetString(%v) = %s contains scientific notation", c.input, got)
			}
		})
	}
}

// TestPSHashtableEntryQuotesKey guards the hashtable key quoting. PowerShell
// parses a bare hyphenated key as an arithmetic expression, and hyphenated
// attribute names are the norm in Active Directory schema extensions.
func TestPSHashtableEntryQuotesKey(t *testing.T) {
	for _, c := range []struct {
		name, key, value, want string
	}{
		{"hyphenated key", "ms-DS-ConsistencyGuid", `"abc"`, `'ms-DS-ConsistencyGuid'="abc"`},
		{"plain key", "extensionAttribute1", `"x"`, `'extensionAttribute1'="x"`},
		{"key is sanitised", "a$b", `"x"`, "'a`$b'=\"x\""},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := PSHashtableEntry(c.key, c.value)
			if got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
			if !strings.HasPrefix(got, "'") {
				t.Errorf("got %s — the key must be quoted or PowerShell reads a hyphen as subtraction", got)
			}
		})
	}
}

// TestPSHashtableEntryEscapesApostrophes guards the single-quoted literal. An
// apostrophe in a key would otherwise close the literal early, and
// custom_attributes keys come straight from the practitioner's configuration.
func TestPSHashtableEntryEscapesApostrophes(t *testing.T) {
	for _, c := range []struct {
		name, key, want string
	}{
		{"apostrophe in key", "O'Brien", `'O''Brien'="x"`},
		{"literal-breaking attempt", `a'+$(whoami)+'b`, "'a''+`$(whoami)+''b'=\"x\""},
		{"no apostrophe is untouched", "plainKey", `'plainKey'="x"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := PSHashtableEntry(c.key, `"x"`)
			if got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}
}

// TestPSHashtableValueDoesNotDoubleQuote is the guard for a defect this pull
// request nearly introduced. SortInnerSlice runs every value through GetString,
// which returns it quoted. Quoting again yields `""Chief""` and makes the
// Set-ADUser hashtable invalid.
func TestPSHashtableValueDoesNotDoubleQuote(t *testing.T) {
	for _, c := range []struct {
		name string
		in   any
		want string
	}{
		{"scalar keeps its single pair of quotes", `"Chief"`, `"Chief"`},
		{"slice is joined, not requoted", []string{`"a"`, `"b"`}, `"a","b"`},
		{"single-element slice", []string{`"only"`}, `"only"`},
		{"empty slice", []string{}, ``},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := PSHashtableValue(c.in)
			if got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
			if strings.Contains(got, `""`) && c.want != `` {
				t.Errorf("got %s — the value was quoted twice", got)
			}
		})
	}

	// End to end through the pair, the way ModifyUser uses them.
	t.Run("through SortInnerSlice, as ModifyUser does", func(t *testing.T) {
		sorted := SortInnerSlice(map[string]any{
			"title": "Chief",
			"multi": []any{"a", "b"},
		})

		if got := PSHashtableEntry("title", PSHashtableValue(sorted["title"])); got != `'title'="Chief"` {
			t.Errorf("scalar: got %s, want 'title'=\"Chief\"", got)
		}
		if got := PSHashtableEntry("multi", PSHashtableValue(sorted["multi"])); got != `'multi'="a","b"` {
			t.Errorf("slice: got %s, want 'multi'=\"a\",\"b\"", got)
		}
	})
}

// TestGetOtherAttributesAcceptsNonStrings guards against the type assertion that
// used to sit here. custom_attributes is free-form JSON, so a number or a
// boolean is entirely ordinary input — and asserting it to string panics, taking
// the provider down rather than returning an error.
func TestGetOtherAttributesAcceptsNonStrings(t *testing.T) {
	for _, c := range []struct {
		name string
		attr map[string]any
		want string
	}{
		{"number", map[string]any{"employeeNumber": float64(4711)}, `@{'employeeNumber'="4711"}`},
		{"bool", map[string]any{"flag": true}, `@{'flag'="true"}`},
		{"string", map[string]any{"title": "Chief"}, `@{'title'="Chief"}`},
		{"hyphenated key", map[string]any{"ms-DS-Foo": "bar"}, `@{'ms-DS-Foo'="bar"}`},
		{"slice of mixed", map[string]any{"multi": []any{"a", float64(2)}}, `@{'multi'="a","2"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %v: %v", c.attr, r)
				}
			}()

			u := &User{CustomAttributes: c.attr}
			got, err := u.getOtherAttributes()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}
}
