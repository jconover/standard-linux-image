# Contributing to Standard Linux Image

Thank you for your interest in contributing to the Standard Linux Image project! This document provides guidelines and instructions for contributing.

## Table of Contents

- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Code Style Guidelines](#code-style-guidelines)
- [Commit Message Format](#commit-message-format)
- [Pull Request Process](#pull-request-process)
- [Testing Requirements](#testing-requirements)
- [Review Process](#review-process)

## How to Contribute

There are several ways to contribute to this project:

1. **Report Bugs**: Open an issue describing the bug, steps to reproduce, and expected behavior
2. **Request Features**: Open an issue describing the feature and its use case
3. **Submit Code**: Fork the repository and submit a pull request
4. **Improve Documentation**: Help improve README, comments, or add examples
5. **Review Pull Requests**: Help review and test other contributors' PRs

### Before You Start

- Check existing [issues](https://github.com/YOUR_ORG/standard-linux-image/issues) to avoid duplicates
- For major changes, open an issue first to discuss the approach
- Ensure your contribution aligns with the project's goals and security standards

## Development Setup

### Prerequisites

Install the following tools on your development machine:

```bash
# Packer (>= 1.9.0)
# Download from https://developer.hashicorp.com/packer/downloads
packer version

# Ansible (>= 2.14)
pip install ansible ansible-lint

# InSpec (>= 5.0)
# Download from https://docs.chef.io/inspec/install/
inspec version

# Optional: Pre-commit hooks
pip install pre-commit
pre-commit install
```

### Clone and Setup

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/standard-linux-image.git
cd standard-linux-image

# Add upstream remote
git remote add upstream https://github.com/YOUR_ORG/standard-linux-image.git

# Initialize Packer plugins
packer init packer/

# Create your variable file for local testing
cp packer/variables.auto.pkrvars.hcl.example packer/variables.auto.pkrvars.hcl
```

### Directory Structure

Familiarize yourself with the project layout:

```
packer/           # Packer templates and variables
ansible/          # Ansible playbooks and roles
  roles/
    base/         # Base OS configuration
    cloud-init/   # Cloud-init setup
    hardening/    # CIS benchmark hardening
    vsphere/      # vSphere-specific configuration
    aws/          # AWS-specific configuration
inspec/           # Compliance testing profiles
scripts/          # Utility scripts
```

## Code Style Guidelines

### Packer (HCL)

- Use 2-space indentation
- Group related variables with comment headers
- Add descriptions to all variables
- Use meaningful names for sources and builds
- Add comments explaining non-obvious configurations

```hcl
# Good example
variable "vm_cpu_count" {
  type        = number
  description = "Number of vCPUs allocated to the VM"
  default     = 2
}

# Bad example
variable "cpu" {
  default = 2
}
```

### Ansible

- Follow [Ansible Best Practices](https://docs.ansible.com/ansible/latest/tips_tricks/ansible_tips_tricks.html)
- Use YAML syntax consistently (no mixing of styles)
- Name all tasks descriptively
- Use fully qualified collection names (FQCN)
- Keep roles focused and single-purpose
- Use `ansible-lint` to check for issues

```yaml
# Good example
- name: Install required packages
  ansible.builtin.dnf:
    name: "{{ base_packages }}"
    state: present
  become: true

# Bad example
- dnf: name=vim state=present
```

### InSpec

- Use meaningful control IDs with prefixes (e.g., `ssh-01`, `firewall-01`)
- Add impact scores and descriptions to all controls
- Reference CIS benchmark sections in control titles
- Use `describe` blocks with clear expectations

```ruby
# Good example
control 'ssh-01' do
  impact 1.0
  title '5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured'
  desc 'The /etc/ssh/sshd_config file should be owned by root with restricted permissions'

  describe file('/etc/ssh/sshd_config') do
    it { should exist }
    its('mode') { should cmp '0600' }
    its('owner') { should eq 'root' }
  end
end
```

### Shell Scripts

- Use `#!/bin/bash` shebang
- Add `set -euo pipefail` for safety
- Quote all variables
- Add comments explaining the purpose
- Use functions for reusable logic

## Commit Message Format

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature or functionality |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `style` | Code style changes (formatting, no logic change) |
| `refactor` | Code refactoring (no feature or fix) |
| `test` | Adding or updating tests |
| `chore` | Maintenance tasks, dependencies |
| `ci` | CI/CD pipeline changes |
| `security` | Security-related changes |

### Scopes

| Scope | Description |
|-------|-------------|
| `packer` | Packer templates |
| `ansible` | Ansible playbooks and roles |
| `inspec` | Compliance profiles |
| `aws` | AWS-specific changes |
| `vsphere` | vSphere-specific changes |
| `ci` | GitHub Actions workflows |

### Examples

```bash
# Feature
feat(ansible): add automatic security updates role

# Bug fix
fix(packer): correct vSphere disk controller type

# Documentation
docs: update README with vSphere prerequisites

# Security
security(ansible): harden SSH cipher configuration

# Multiple scopes
feat(ansible,inspec): implement auditd configuration and compliance checks
```

### Commit Message Body

For complex changes, include:

- **What**: Brief description of the change
- **Why**: Motivation or context
- **How**: Implementation approach (if not obvious)

```
feat(ansible): implement CIS Level 1 filesystem hardening

Add filesystem hardening tasks aligned with CIS Rocky Linux 9 Benchmark:
- Configure separate partitions for /var, /var/log, /tmp
- Set noexec, nosuid, nodev mount options on /tmp
- Disable automounting and USB storage

Addresses requirements in PRD section "Filesystem & Partitioning"
```

## Pull Request Process

### Before Submitting

1. **Sync with upstream**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run local validation**:
   ```bash
   # Validate Packer templates
   packer validate packer/rocky-aws.pkr.hcl
   packer validate -var-file="packer/variables.auto.pkrvars.hcl" packer/rocky-vsphere.pkr.hcl

   # Lint Ansible
   ansible-lint ansible/

   # Check InSpec syntax
   inspec check inspec/cis-benchmark/
   ```

3. **Test your changes** (see [Testing Requirements](#testing-requirements))

4. **Update documentation** if needed

### Submitting

1. Push your branch to your fork
2. Open a pull request against `main`
3. Fill out the PR template completely
4. Link any related issues

### PR Title Format

Use the same format as commit messages:

```
feat(ansible): add automatic security updates role
```

## Testing Requirements

All contributions must include appropriate testing:

### Packer Changes

- Validate template syntax: `packer validate <template>`
- Test build locally if possible (AWS free tier or vSphere lab)
- Verify provisioners execute correctly

### Ansible Changes

- Run `ansible-lint` with no errors
- Test playbook syntax: `ansible-playbook --syntax-check`
- Test role in isolation if possible
- For hardening changes, verify with InSpec

### InSpec Changes

- Validate profile: `inspec check inspec/cis-benchmark/`
- Test controls against a target system
- Ensure controls map to CIS benchmark sections
- Add both positive and negative test cases

### Required Checks

All PRs must pass:

- [ ] Packer template validation
- [ ] Ansible linting
- [ ] InSpec profile validation
- [ ] CI pipeline checks
- [ ] Code review approval

## Review Process

### What Reviewers Look For

1. **Functionality**: Does the code work as intended?
2. **Security**: Are there any security implications?
3. **Style**: Does it follow project conventions?
4. **Testing**: Are changes adequately tested?
5. **Documentation**: Is documentation updated?
6. **Backwards Compatibility**: Does it break existing functionality?

### Review Timeline

- Initial review within 3 business days
- Follow-up reviews within 2 business days
- Complex PRs may require additional review time

### Addressing Feedback

- Respond to all comments
- Push additional commits to address feedback
- Request re-review when ready
- Squash commits before final merge (if requested)

### Merge Requirements

- At least 1 approving review
- All CI checks passing
- No unresolved conversations
- Branch up to date with main

## Questions?

If you have questions about contributing:

1. Check existing documentation
2. Search closed issues and PRs
3. Open a discussion or issue

Thank you for contributing to Standard Linux Image!
