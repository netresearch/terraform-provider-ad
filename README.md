<a href="https://terraform.io">
    <img src="https://github.com/hashicorp/terraform-provider-azurerm/raw/main/.github/tf.png" alt="Terraform logo" title="Terraform" align="left" height="50" />
</a>

# Terraform Provider for Windows Active Directory (AD)

> ⚠️ **This is a fork of the official [Terraform AD provider](https://github.com/hashicorp/terraform-provider-ad) with fixes**

Fixes we've applied: 
- [Updated the dependencies](https://github.com/netresearch/terraform-provider-ad/commit/419b5226deda2c227074ca63e28dfbf72986ed72)
- [Fixed UTF-16 issues](https://github.com/hashicorp/terraform-provider-ad/pull/190) by [@sthetz](https://github.com/sthetz)

[![Releases](https://img.shields.io/github/release/netresearch/terraform-provider-ad.svg)](https://github.com/netresearch/terraform-provider-ad/releases)
[![LICENSE](https://img.shields.io/github/license/netresearch/terraform-provider-ad.svg)](https://github.com/netresearch/terraform-provider-ad/blob/main/LICENSE)
![Unit tests](https://github.com/netresearch/terraform-provider-ad/workflows/Unit%20tests/badge.svg)

This Windows AD provider for Terraform allows you to manage users, groups and group policies in your AD installation.

This provider is a technical preview, which means it's a community supported project. It still requires extensive testing and polishing to mature into a HashiCorp officially supported project. Please [file issues](https://github.com/netresearch/terraform-provider-ad/issues/new/choose) generously and detail your experience while using the provider. We welcome your feedback.

By using the software in this repository (the AD provider), you acknowledge that:
* The AD provider is still in development, may change, and has not been released as a commercial product by HashiCorp and is not currently supported in any way by HashiCorp.
* The AD provider is provided on an "as-is" basis, and may include bugs, errors, or other issues.
* The AD provider is NOT INTENDED FOR PRODUCTION USE, use of the Software may result in unexpected results, loss of data, or other unexpected results, and HashiCorp disclaims any and all liability resulting from use of the AD provider.
* HashiCorp reserves all rights to make all decisions about the features, functionality and commercial release (or non-release) of the AD provider, at any time and without any obligation or liability whatsoever.

## Requirements

* [Terraform](https://www.terraform.io/downloads.html) version 0.12.x+
* [Windows Server](https://www.microsoft.com/en-us/windows-server) 2012R2 or greater
* [Go](https://golang.org/doc/install) version 1.16.x+

## Getting Started

If this is your first time here, you can get an overview of the provider by reading HashiCorp's [introductory blog post](https://www.hashicorp.com/blog/manage-active-directory-objects-new-windows-ad-provider-hashicorp-terraform). Otherwise, start by downloading a copy of the latest build from the [registry](https://registry.terraform.io/providers/netresearch/ad/latest).

Once you have the plugin installed, review the [docs](docs/) folder to understand which configuration options are available. You can find examples and more in [our examples folder](examples/). Don't forget to run `terraform init` in your Terraform configuration directory to allow Terraform to detect the provider plugin.

## Contributing

We welcome your contribution. Please understand that the experimental nature of this repository means that contributing code may be a bit of a moving target. If you have an idea for an enhancement or bug fix, and want to take on the work yourself, please first [create an issue](https://github.com/netresearch/terraform-provider-ad/issues/new/choose) so that we can discuss the implementation with you before you proceed with the work.

You can review our [contribution guide](_about/CONTRIBUTING.md) to begin. You can also check out our [frequently asked questions](_about/FAQ.md).
