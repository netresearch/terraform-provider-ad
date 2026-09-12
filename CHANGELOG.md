## v0.5.0 (netresearch fork, September 12, 2026)

FEATURES:
* **Resource**: `ad_user`: new write-only argument `initial_password_wo`, with the companion counter `initial_password_wo_version`. Terraform never writes a write-only value to state or to the plan file, so the Active Directory password is kept out of both — which `Sensitive` alone cannot do. Requires Terraform 1.11 or later. Existing configurations are unaffected: `initial_password` keeps working exactly as before, on every Terraform version. ([#31](https://github.com/netresearch/terraform-provider-ad/pull/31))

BUGFIXES:
* **Resource**: `ad_user`: numeric `custom_attributes` are written to Active Directory as plain numbers again. They were formatted with `strconv.FormatFloat(…, 'E', …)`, so `1000000` reached the directory as the literal text `1E+06`. ([#32](https://github.com/netresearch/terraform-provider-ad/pull/32), adopting [hashicorp#173](https://github.com/hashicorp/terraform-provider-ad/pull/173))
* **Resource**: `ad_user`: a non-string value in `custom_attributes` no longer panics the provider. `getOtherAttributes` asserted every value to `string`, which `custom_attributes` — free-form JSON — readily violates. ([#32](https://github.com/netresearch/terraform-provider-ad/pull/32), adopting [hashicorp#173](https://github.com/hashicorp/terraform-provider-ad/pull/173))
* **Resource**: `ad_user`: hyphenated `custom_attributes` names such as `ms-DS-ConsistencyGuid` now survive. PowerShell parses a bare hyphenated hashtable key as an arithmetic expression, and two of the three places that build those hashtables did not quote the key. The third did not quote its values either. All three now share one helper. ([#32](https://github.com/netresearch/terraform-provider-ad/pull/32), adopting [hashicorp#173](https://github.com/hashicorp/terraform-provider-ad/pull/173))
* **Resource**: `ad_group_membership`: a deliberately empty group can be expressed again; `MinItems: 1` made it impossible to declare a group with no members. ([#32](https://github.com/netresearch/terraform-provider-ad/pull/32), adopting [hashicorp#166](https://github.com/hashicorp/terraform-provider-ad/pull/166))
* **Resource**: `ad_gplink`: GPO GUIDs are compared case-insensitively. Active Directory returns them in whichever casing it stored them, so a linked GPO was intermittently reported as unlinked. ([#32](https://github.com/netresearch/terraform-provider-ad/pull/32))
* **Resource**: `ad_group_membership`: membership changes are split across several `Add-`/`Remove-ADGroupMember` calls instead of one unbounded command, which overran the 8191-character Windows command-line limit on larger groups. The split is by rendered length rather than by member count, since a distinguished name is an order of magnitude longer than a GUID. ([#32](https://github.com/netresearch/terraform-provider-ad/pull/32))
* **Resource**: `ad_gpo_security`: a `registry_values` line with fewer than three comma-separated fields no longer panics the provider. The three fields were read positionally with no length check, while the identical access in `registry_keys` was already guarded. ([#32](https://github.com/netresearch/terraform-provider-ad/pull/32))
* **Resource**: `ad_user`: `cannot_change_password` reports the account's real setting. It was derived from `userAccountControl` bit `0x40`, which Active Directory does not use for this — the setting is a deny ACE on the Change Password right — so the attribute read `false` for every account. `Get-ADUser` already returns the correct value and the derivation was overwriting it. ([#32](https://github.com/netresearch/terraform-provider-ad/pull/32))
* **Resource**: `ad_group_membership`: members named by SAM account name, distinguished name, common name or SID no longer produce a diff on every plan. The schema documents all of these as interchangeable with a GUID, but members were compared by GUID alone and the read wrote GUIDs back to state unconditionally — so any configuration not written in GUIDs disagreed with its own state forever, and Terraform proposed removing and re-adding every member. Comparison now considers every identifier form the directory returns, case-insensitively, and the read keeps the spelling the configuration uses. Members added outside Terraform still appear as their GUID, so drift is still reported. ([#33](https://github.com/netresearch/terraform-provider-ad/pull/33))

NOTES:
* **Resource**: `ad_user`: `initial_password` and `initial_password_wo` are mutually exclusive. Using `initial_password` on Terraform 1.11 or later now produces a warning pointing at the write-only alternative; on older clients it stays silent, since the alternative is not available there. ([#31](https://github.com/netresearch/terraform-provider-ad/pull/31))
* **Resource**: `ad_user`: a write-only value produces no diff of its own, so `initial_password_wo_version` is the only signal the provider has that the password changed. Increment it to re-apply. ([#31](https://github.com/netresearch/terraform-provider-ad/pull/31))

## v0.4.1 (netresearch fork, September 11, 2026)

SECURITY:
* **Resource**: `ad_user`: `initial_password` is now marked `Sensitive` ([GHSA-rj7j-hc27-42gj](https://github.com/netresearch/terraform-provider-ad/security/advisories/GHSA-rj7j-hc27-42gj)). Terraform previously rendered the Active Directory account password in cleartext in `terraform plan` output, which is read wherever plans are surfaced — CI job logs, pull request comments and Terraform Cloud run logs. The value is still stored in cleartext in state and in the JSON plan file, as Terraform does for every attribute; the JSON plan now carries `after_sensitive` so a consumer can tell which values are marked. ([#27](https://github.com/netresearch/terraform-provider-ad/pull/27))
* **Provider**: `winrm_password` is now marked `Sensitive`. Provider configuration is not part of plan output, so this changes no rendering today — it is the correct declaration for a credential and covers `TF_LOG` and the JSON plan's `configuration` block. ([#27](https://github.com/netresearch/terraform-provider-ad/pull/27))
* **CI**: release notes are generated from the current version's CHANGELOG section again; the quit pattern had not matched this fork's headings, so every release body carried the complete history. ([#27](https://github.com/netresearch/terraform-provider-ad/pull/27))

THANKS:
* @kta1kri reported the `initial_password` disclosure privately through a GitHub security advisory, with a complete write-up: the affected declaration, the consumer that proves the value is the real password, a credential-free reproduction, and the scope they had already ruled out. Both of their exclusions held up when we checked them. Reported and held privately throughout.

## v0.4.0 (netresearch fork, August 26, 2026)

* dependencies: CI and release builds now use Go 1.27.0 (`.go-version`); the `go` directive stays at 1.25.8 ([#22](https://github.com/netresearch/terraform-provider-ad/pull/22))
* dependencies: all Go dependencies updated across the module graph ([#23](https://github.com/netresearch/terraform-provider-ad/pull/23))
* internal: `interface{}` replaced by `any` across the codebase via `go fix`; one map-copy loop replaced by `maps.Copy` ([#22](https://github.com/netresearch/terraform-provider-ad/pull/22))
* tooling: pinned golangci-lint updated to v2.13.1 ([#24](https://github.com/netresearch/terraform-provider-ad/pull/24))

<!-- Upstream hashicorp/terraform-provider-ad history below; the netresearch fork re-versioned from v0.1.0. -->

## 0.5.0 (March 28, 2024)

* dependencies: update go to `1.21` [GH-187]
* dependencies: update `terraform-plugin-sdk` to `v2.33.0` [GH-187]

## 0.4.4 (April 05, 2022)

IMPROVEMENTS:
* **Data Source**: `ad_user`: Add `distinguished_name` attribute to data source.
* **Data Source**: `ad_group`: Add `distinguished_name` attribute to data source.
* **Resource**: `ad_group`: Add `distinguished_name` attribute to resource.
* **Resource**: `ad_user`: Add `distinguished_name` attribute to resource.
* **provider**: Ability to define a specific domain controller.
* **provider**: Support for authentication via Kerberos keytab files


## 0.4.3 (June 10, 2021)

FEATURES:
 * **Provider**: Support for "Double Hop" authentication ([#117](https://github.com/hashicorp/terraform-provider-ad/pull/117)) 

IMPROVEMENTS:
* **Data Source**: `ad_computer`: Introduce `computer_id` field. ([#118](https://github.com/hashicorp/terraform-provider-ad/pull/118)) 
* **Data Source**: `ad_ou`: Introduce `ou_id` field. ([#118](https://github.com/hashicorp/terraform-provider-ad/pull/118)) 

BUGFIXES:
* **Docs**: Fixed formatting issues ([#100](https://github.com/hashicorp/terraform-provider-ad/pull/100))
* **Resource**: `ad_group` Fix issue when moving group ([#109](https://github.com/hashicorp/terraform-provider-ad/pull/109)) 
* **Resource**: `ad_group` Fix issue when moving group ([#112](https://github.com/hashicorp/terraform-provider-ad/pull/112)) 
* **Resource**: `ad_ou` Fix issue when moving OU ([#105](https://github.com/hashicorp/terraform-provider-ad/pull/105)) 

## 0.4.2 (April 21, 2021)

BUGFIXES:
* **Resource:** `ad_user`: Fix bug when removing user attributes. ([#77](https://github.com/hashicorp/terraform-provider-ad/pull/77))
* **Resource:** `ad_group`: Use correct command when updating AD groups. ([#83](https://github.com/hashicorp/terraform-provider-ad/pull/83))
* **Resource:** `ad_group`: Fix category name. ([#69](https://github.com/hashicorp/terraform-provider-ad/pull/69))

FEATURES:
* **provider:** Execute commands as current user when running on windows. ([#80](https://github.com/hashicorp/terraform-provider-ad/pull/80))

IMPROVEMENTS:
* **Resource:** `ad_computer`: Add description attribute to resource. ([#85](https://github.com/hashicorp/terraform-provider-ad/pull/85))
* **Resource:** `ad_group`: Add description attribute to resource. ([#93](https://github.com/hashicorp/terraform-provider-ad/pull/93))
* **Resource:** `ad_group, ad_user, ad_computer`: Add a computed field that holds the object's SID. ([#76](https://github.com/hashicorp/terraform-provider-ad/pull/76))
* **provider**: Upgraded the terraform plugin SDK version to 2.5.0
* **provider**: Extract error messages from CLIXML. ([#74](https://github.com/hashicorp/terraform-provider-ad/pull/74))

## 0.4.1 (January 18, 2021)

**BREAKING CHANGES:**

If you are using the `ad_group` or `ad_user` datasources you will have to update some fields in your terraform configuration.

* **Resource:** `ad_group` datasource now use the attribute `group_id` instead of `guid`. ([#69](https://github.com/hashicorp/terraform-provider-ad/pull/69))
* **Resource:** `ad_user` datasource now use the attribute `user_id` instead of `guid`. ([#69](https://github.com/hashicorp/terraform-provider-ad/pull/69))

BUGFIXES:
* **Resource:** `ad_group_membership` uses parameter `Members` instead of `Member`. ([#68](https://github.com/hashicorp/terraform-provider-ad/pull/68))
* **Kerberos Authentication:** Kerberos now respects the protocol setting and correctly uses https when instructed, instead of always using `http`. ([#66](https://github.com/hashicorp/terraform-provider-ad/pull/66))

FEATURES:
* **Resource:** `ad_user`: Added many standard attributes. ([#63](https://github.com/hashicorp/terraform-provider-ad/pull/63))
* **Resource:** `ad_user`: Added support for custom attributes. ([#73](https://github.com/hashicorp/terraform-provider-ad/pull/73))

## 0.4.0 (December 17, 2020)

FEATURES:
* **New Auth method:** The provider now supports Kerberos authentication.
* **New Auth method:** The provider now supports NTLM authentication. ([#56](https://github.com/hashicorp/terraform-provider-ad/pull/56))

## 0.3.0 (November 06, 2020)

FEATURES:
* **New Resource:** `ad_group_membership`

BUGFIXES:
* **Resource:** `ad_user` now supports moving users between containers ([#49](https://github.com/hashicorp/terraform-provider-ad/pull/49))

## 0.2.0 (September 28, 2020)

IMPROVEMENTS:
* Upgraded to the provider SDK v2.0.0 ([#37](https://github.com/hashicorp/terraform-provider-ad/pull/37))

BUGFIXES:
* **Resource:** `ad_gpo_security` now sets the correct Machine Extension Name in the GPO ([#43](https://github.com/hashicorp/terraform-provider-ad/pull/43/))

## 0.1.0 (July 29, 2020)

FEATURES:

* **New Resource:** `ad_user`
* **New Resource:** `ad_group`
* **New Resource:** `ad_computer`
* **New Resource:** `ad_ou`
* **New Resource:** `ad_gpo`
* **New Resource:** `ad_gpo_security`
* **New Resource:** `ad_gplink`

* **New Datasource:**   `ad_user`
* **New Datasource:**   `ad_group`
* **New Datasource:**   `ad_gpo`
* **New Datasource:**   `ad_computer`
* **New Datasource:**   `ad_ou`
