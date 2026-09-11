package ad

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// The SDK renders ConflictsWith as "Conflicting configuration arguments".
var regexpConflictsWith = regexp.MustCompile(`(?i)conflict`)

// TestAccResourceADUser_writeOnlyPassword covers the branch that no unit test can
// reach: the update path keyed on initial_password_wo_version. A write-only value
// is null in state, so d.HasChange("initial_password_wo") can never fire and the
// version counter is the only signal that the password changed. If that wiring
// breaks, step three below plans and applies without ever calling
// Set-ADAccountPassword, and the account silently keeps its old password.
//
// Requires Terraform 1.11 or later and a reachable domain. Like every other
// acceptance test here it runs only under TF_ACC and is not part of CI.
func TestAccResourceADUser_writeOnlyPassword(t *testing.T) {
	envVars := []string{
		"TF_VAR_ad_user_display_name",
		"TF_VAR_ad_user_sam",
		"TF_VAR_ad_user_password",
		"TF_VAR_ad_user_principal_name",
		"TF_VAR_ad_user_container",
	}

	username := os.Getenv("TF_VAR_ad_user_sam")
	resourceName := "ad_user.wo"

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t, envVars) },
		Providers: testAccProviders,
		CheckDestroy: resource.ComposeTestCheckFunc(
			testAccResourceADUserExists(resourceName, username, false),
		),
		Steps: []resource.TestStep{
			{
				Config: testAccResourceADUserConfigWriteOnly(1),
				Check: resource.ComposeTestCheckFunc(
					testAccResourceADUserExists(resourceName, username, true),
					// The write-only value must not reach state. This is the whole
					// point of the attribute, so assert it rather than assume it.
					resource.TestCheckNoResourceAttr(resourceName, "initial_password_wo"),
					resource.TestCheckResourceAttr(resourceName, "initial_password_wo_version", "1"),
				),
			},
			{
				// Bumping the version must produce a diff and re-apply the password.
				Config: testAccResourceADUserConfigWriteOnly(2),
				Check: resource.ComposeTestCheckFunc(
					testAccResourceADUserExists(resourceName, username, true),
					resource.TestCheckNoResourceAttr(resourceName, "initial_password_wo"),
					resource.TestCheckResourceAttr(resourceName, "initial_password_wo_version", "2"),
				),
			},
			{
				// Re-applying the same version must be a no-op, otherwise every plan
				// would reset the account password.
				Config:   testAccResourceADUserConfigWriteOnly(2),
				PlanOnly: true,
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				// Neither is readable back from the directory.
				ImportStateVerifyIgnore: []string{"initial_password_wo", "initial_password_wo_version"},
			},
		},
	})
}

// TestAccResourceADUser_writeOnlyConflictsWithInitialPassword asserts the mutual
// exclusion is enforced at plan time rather than silently applying one of them.
func TestAccResourceADUser_writeOnlyConflictsWithInitialPassword(t *testing.T) {
	envVars := []string{
		"TF_VAR_ad_user_display_name",
		"TF_VAR_ad_user_sam",
		"TF_VAR_ad_user_password",
		"TF_VAR_ad_user_principal_name",
		"TF_VAR_ad_user_container",
	}

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t, envVars) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config:      testAccResourceADUserConfigBothPasswords(),
				ExpectError: regexpConflictsWith,
				PlanOnly:    true,
			},
		},
	})
}

func testAccResourceADUserConfigWriteOnly(version int) string {
	return fmt.Sprintf(`%s
	resource "ad_user" "wo" {
	  principal_name              = var.ad_user_principal_name
	  sam_account_name            = var.ad_user_sam
	  display_name                = var.ad_user_display_name
	  container                   = %q
	  initial_password_wo         = var.ad_user_password
	  initial_password_wo_version = %d
	}`, defaultVariablesSection(), os.Getenv("TF_VAR_ad_user_container"), version)
}

func testAccResourceADUserConfigBothPasswords() string {
	return fmt.Sprintf(`%s
	resource "ad_user" "wo" {
	  principal_name              = var.ad_user_principal_name
	  sam_account_name            = var.ad_user_sam
	  display_name                = var.ad_user_display_name
	  container                   = %q
	  initial_password            = var.ad_user_password
	  initial_password_wo         = var.ad_user_password
	  initial_password_wo_version = 1
	}`, defaultVariablesSection(), os.Getenv("TF_VAR_ad_user_container"))
}
