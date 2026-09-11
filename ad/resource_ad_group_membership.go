package ad

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/winrmhelper"
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
	toks := strings.Split(d.Id(), "_")

	gm, err := winrmhelper.NewGroupMembershipFromHost(meta.(*config.ProviderConf), toks[0])
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
	_ = d.Set("group_id", toks[0])
	return nil
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

	membershipUUID, err := uuid.GenerateUUID()
	if err != nil {
		return fmt.Errorf("while generating UUID to use as unique membership ID: %s", err)
	}

	id := fmt.Sprintf("%s_%s", gm.GroupGUID, membershipUUID)
	d.SetId(id)

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
