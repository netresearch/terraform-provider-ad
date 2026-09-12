package winrmhelper

import (
	"fmt"
	"testing"
)

// RunPSCommand takes one command string where callers used to hand NewPSCommand
// a slice. That is only safe because every place NewPSCommand consumes the slice
// joins it with a single space — the final join, and the Invoke-Command script
// block. This pins that: pre-joining the caller's parts must produce the exact
// same command line, under every combination of the two switches that change how
// the slice is consumed.
func TestPreJoinedCommandIsIdenticalToASlice(t *testing.T) {
	for _, invoke := range []bool{false, true} {
		for _, json := range []bool{false, true} {
			t.Run(fmt.Sprintf("invoke=%t/json=%t", invoke, json), func(t *testing.T) {
				opts := CreatePSCommandOpts{
					InvokeCommand:   invoke,
					PassCredentials: true,
					JSONOutput:      json,
					Username:        "user",
					Password:        "secret",
					Server:          "dc01",
				}

				split := NewPSCommand([]string{"Get-ADUser -Identity x", "-Properties *"}, opts).String()
				joined := NewPSCommand([]string{"Get-ADUser -Identity x -Properties *"}, opts).String()

				if split != joined {
					t.Errorf("pre-joining changed the command:\n split:  %s\n joined: %s", split, joined)
				}
			})
		}
	}
}
