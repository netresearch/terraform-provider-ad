# AI Agent Guidelines

## Project Overview

This is a Terraform provider for Active Directory, originally forked from HashiCorp's terraform-provider-ad. It enables managing Active Directory resources (users, groups, OUs, GPOs, etc.) via Terraform.

## Architecture

- **Language**: Go 1.24+
- **Framework**: Terraform Plugin SDK v2
- **Communication**: WinRM to Windows Domain Controllers
- **Authentication**: Kerberos or NTLM

## Key Directories

- `ad/` - Provider implementation (resources, data sources)
- `docs/` - Generated documentation for Terraform Registry
- `examples/` - Usage examples for each resource
- `templates/` - Documentation templates

## Development Workflow

```bash
# Run tests
make test

# Run acceptance tests (requires AD environment)
make testacc

# Build the provider
make build

# Generate documentation
make generate
```

## Testing Requirements

- Unit tests: Run locally without external dependencies
- Acceptance tests: Require a Windows Domain Controller with WinRM enabled

## Code Style

- Follow standard Go conventions (gofmt, golint)
- Resources use `schema.Resource` pattern
- Use meaningful error messages with context
- Document all exported functions

## Security Considerations

- Never log credentials or sensitive data
- Validate all user inputs
- Use secure WinRM connections (HTTPS) when possible
- Handle Kerberos tickets securely

## Common Tasks

### Adding a New Resource

1. Create resource file in `ad/` (e.g., `resource_ad_newresource.go`)
2. Register in `ad/provider.go`
3. Add documentation template in `templates/`
4. Add examples in `examples/`
5. Run `make generate` to create docs

### Debugging

```bash
# Enable debug logging
TF_LOG=DEBUG terraform apply

# Run specific test
go test -v ./ad -run TestAccADUser
```
