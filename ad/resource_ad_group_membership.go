package ad

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/winrmhelper"
	"uuid"
)

func resourceADGroupMembership() *schema.Resource {
	return &schema.Resource{
		Description: "`ad_group_membership` manages the members of a given Active Directory group.",
		Create:      resourceADGroupMembershipCreate,
		Read:        resourceADGroupMembershipRead,
		Update:      resourceADGroupMembershipUpdate,
		Delete:      resourceADGroupMembershipDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"group_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The ID of the group. This can be a GUID, a SID, a Distinguished Name, or the SAM Account Name of the group.",
				ForceNew:    true,
			},
			"group_members": {
				Type:        schema.TypeSet,
				Required:    true,
				Description: "A list of member AD Principals. Each principal can be identified by its GUID, SID, Distinguished Name, or SAM Account Name. Only one is required",
				Elem:        &schema.Schema{Type: schema.TypeString},
				// No MinItems: a group that is deliberately empty has to be
				// expressible, and the resource handles an empty set correctly.
			},
		},
	}
}

func resourceADGroupMembershipRead(d *schema.ResourceData, meta any) error {
	groupID := membershipGroupID(d.Id())

	gm, err := winrmhelper.NewGroupMembershipFromHost(meta.(*config.ProviderConf), groupID)
	if err != nil {
		return err
	}
	// Keep the identifier form the configuration uses for members that are still
	// present. Writing GUIDs unconditionally made every configuration that names
	// members by SAM account name or distinguished name diff forever.
	configured := []string{}
	if raw, ok := d.GetOk("group_members"); ok {
		for _, m := range raw.(*schema.Set).List() {
			configured = append(configured, m.(string))
		}
	}

	memberList := winrmhelper.ReconcileMemberIdentifiers(gm.GroupMembers, configured)
	_ = d.Set("group_members", memberList)
	_ = d.Set("group_id", groupID)
	return nil
}

// membershipID builds the resource id for a group membership: the configured
// group_id, an underscore, and a fresh GUID that only has to be unique.
//
// The group_id can be a SAM account name or a distinguished name, and either may
// contain an underscore, so membershipGroupID recovers it by removing the GUID
// suffix rather than by splitting at the first underscore. String is called
// explicitly rather than left to the %s verb — the verb reaches it either way,
// since the method has a value receiver — so that the conversion is visible at
// the one place that decides what a resource id looks like. The id lands in
// serialised state and is what `terraform import` has to be handed back, so
// anything that stops it being canonical text belongs in a diff, not in a verb.
func membershipID(groupID string) string {
	return fmt.Sprintf("%s_%s", groupID, uuid.New().String())
}

// membershipGroupID returns the group_id part of a resource id built by
// membershipID. It removes the text from the last underscore on only when that
// text is a canonical GUID; any other id is taken whole as the group_id, which
// keeps an import by a bare group name containing an underscore intact.
func membershipGroupID(id string) string {
	i := strings.LastIndex(id, "_")
	if i < 0 || parseGUID(id[i+1:]) != nil {
		return id
	}
	return id[:i]
}

func resourceADGroupMembershipCreate(d *schema.ResourceData, meta any) error {
	gm, err := winrmhelper.NewGroupMembershipFromState(d)
	if err != nil {
		return err
	}

	err = gm.Create(meta.(*config.ProviderConf))
	if err != nil {
		return err
	}

	d.SetId(membershipID(gm.GroupID))

	return nil
}

func resourceADGroupMembershipUpdate(d *schema.ResourceData, meta any) error {
	gm, err := winrmhelper.NewGroupMembershipFromState(d)
	if err != nil {
		return err
	}

	err = gm.Update(meta.(*config.ProviderConf), gm.GroupMembers)
	if err != nil {
		return err
	}

	return resourceADGroupMembershipRead(d, meta)
}

func resourceADGroupMembershipDelete(d *schema.ResourceData, meta any) error {
	gm, err := winrmhelper.NewGroupMembershipFromState(d)
	if err != nil {
		return err
	}

	err = gm.Delete(meta.(*config.ProviderConf))
	if err != nil {
		return err
	}

	d.SetId("")
	return nil
}
