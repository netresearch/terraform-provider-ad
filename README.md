<a href="https://terraform.io">
    <img src="https://github.com/hashicorp/terraform-provider-azurerm/raw/main/.github/tf.png" alt="Terraform logo" title="Terraform" align="left" height="50" />
</a>

# Terraform Provider for Windows Active Directory (AD)

> ⚠️ **This is a maintained fork of [hashicorp/terraform-provider-ad](https://github.com/hashicorp/terraform-provider-ad), which HashiCorp has archived.**
>
> Upstream is read-only: its last commit was 2025-05-28 and it accepts no further issues or pull requests. This fork continues the provider and is published to the Terraform Registry as [`netresearch/ad`](https://registry.terraform.io/providers/netresearch/ad/latest).

What this fork changes on top of upstream:

- **Fixes UTF-16 / unicode encoding issues** — from upstream [PR #190](https://github.com/hashicorp/terraform-provider-ad/pull/190) by [@sthetz](https://github.com/sthetz), which was never merged upstream and, now that the repository is archived, never will be.
- **Adds `username` to the `ad_user` data source**, equivalent to the `-Name` argument.
- **Unvendors the dependency tree** ([`419b522`](https://github.com/netresearch/terraform-provider-ad/commit/419b5226deda2c227074ca63e28dfbf72986ed72)) and keeps dependencies current, including security updates that upstream stopped receiving.
- **Releases from our own pipeline** — upstream released through HashiCorp-internal infrastructure that a fork cannot use.

Since upstream is archived, please [file issues here](https://github.com/netresearch/terraform-provider-ad/issues/new/choose) rather than against HashiCorp.

[![Releases](https://img.shields.io/github/release/netresearch/terraform-provider-ad.svg)](https://github.com/netresearch/terraform-provider-ad/releases)
[![LICENSE](https://img.shields.io/github/license/netresearch/terraform-provider-ad.svg)](https://github.com/netresearch/terraform-provider-ad/blob/main/LICENSE)
![Unit tests](https://github.com/netresearch/terraform-provider-ad/workflows/Unit%20tests/badge.svg)

This Windows AD provider for Terraform allows you to manage users, groups and group policies in your AD installation.

This provider is community supported. HashiCorp shipped it as a technical preview and has since archived the upstream repository, so it will not become an officially supported HashiCorp project. Please [file issues](https://github.com/netresearch/terraform-provider-ad/issues/new/choose) generously and detail your experience while using the provider. We welcome your feedback.

By using the software in this repository (the AD provider), you acknowledge that:
* The AD provider is still in development, may change, and has not been released as a commercial product by HashiCorp and is not currently supported in any way by HashiCorp.
* The AD provider is provided on an "as-is" basis, and may include bugs, errors, or other issues.
* The AD provider is NOT INTENDED FOR PRODUCTION USE, use of the Software may result in unexpected results, loss of data, or other unexpected results, and HashiCorp disclaims any and all liability resulting from use of the AD provider.
* HashiCorp reserves all rights to make all decisions about the features, functionality and commercial release (or non-release) of the AD provider, at any time and without any obligation or liability whatsoever.

## Requirements

* [Terraform](https://www.terraform.io/downloads.html) version 0.12.x+
* [Windows Server](https://www.microsoft.com/en-us/windows-server) 2012R2 or greater
* [Go](https://golang.org/doc/install) version 1.25.x+ (only to build from source; see `go.mod`)

## Getting Started

If this is your first time here, you can get an overview of the provider by reading HashiCorp's [introductory blog post](https://www.hashicorp.com/blog/manage-active-directory-objects-new-windows-ad-provider-hashicorp-terraform). Otherwise, start by downloading a copy of the latest build from the [registry](https://registry.terraform.io/providers/netresearch/ad/latest).

Once you have the plugin installed, review the [docs](docs/) folder to understand which configuration options are available. You can find examples and more in [our examples folder](examples/). Don't forget to run `terraform init` in your Terraform configuration directory to allow Terraform to detect the provider plugin.

## Contributing

We welcome your contribution. Please understand that the experimental nature of this repository means that contributing code may be a bit of a moving target. If you have an idea for an enhancement or bug fix, and want to take on the work yourself, please first [create an issue](https://github.com/netresearch/terraform-provider-ad/issues/new/choose) so that we can discuss the implementation with you before you proceed with the work.

You can review our [contribution guide](_about/CONTRIBUTING.md) to begin. You can also check out our [frequently asked questions](_about/FAQ.md).
