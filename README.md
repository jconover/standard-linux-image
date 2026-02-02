# Standard Linux Image

[![Build Status](https://github.com/YOUR_ORG/standard-linux-image/actions/workflows/build.yml/badge.svg)](https://github.com/YOUR_ORG/standard-linux-image/actions/workflows/build.yml)
[![CIS Compliance](https://img.shields.io/badge/CIS%20Benchmark-Level%201-green)](https://www.cisecurity.org/cis-benchmarks)
[![Latest Release](https://img.shields.io/github/v/release/YOUR_ORG/standard-linux-image)](https://github.com/YOUR_ORG/standard-linux-image/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Overview

A production-ready, hardened Linux VM template builder for multi-cloud deployments. This project creates standardized, CIS-compliant Rocky Linux images that can be deployed as both vSphere templates and AWS AMIs using Packer, Ansible, and InSpec.

## Purpose

- Provide a **consistent base image** across vSphere and AWS environments
- Ensure **security compliance** with CIS Benchmark Level 1 hardening
- Enable **fully automated**, repeatable image builds
- Simplify **maintenance and auditing** of golden images

## Features

- **Multi-Platform Support**: Build identical images for vSphere and AWS
- **Rocky Linux 9 & 10**: Support for current and future LTS releases
- **CIS Hardening**: Automated security hardening aligned with CIS Benchmarks
- **Cloud-Init Ready**: First-boot customization for hostname, SSH keys, and networking
- **Compliance Testing**: Built-in InSpec profiles for validation
- **CI/CD Integration**: GitHub Actions workflows for automated builds
- **Encrypted Volumes**: AWS AMIs built with EBS encryption enabled
- **Content Library**: vSphere templates exported to Content Library

## Quick Start

```bash
# Clone the repository
git clone https://github.com/YOUR_ORG/standard-linux-image.git
cd standard-linux-image

# Initialize Packer plugins
packer init packer/

# Build for AWS (requires AWS credentials)
packer build -var-file="packer/variables.auto.pkrvars.hcl" packer/rocky-aws.pkr.hcl

# Build for vSphere (requires vCenter access)
packer build -var-file="packer/variables.auto.pkrvars.hcl" packer/rocky-vsphere.pkr.hcl
```

## Prerequisites

Before building images, ensure you have the following installed and configured:

| Tool | Version | Purpose |
|------|---------|---------|
| [Packer](https://developer.hashicorp.com/packer/downloads) | >= 1.9.0 | Image builder |
| [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/) | >= 2.14 | Configuration management |
| [InSpec](https://docs.chef.io/inspec/install/) | >= 5.0 | Compliance testing |
| [AWS CLI](https://aws.amazon.com/cli/) | >= 2.0 | AWS builds (if targeting AWS) |
| vSphere Access | vCenter 7.0+ | vSphere builds (if targeting vSphere) |

### AWS Requirements

- AWS credentials configured (`aws configure` or environment variables)
- VPC with public subnet for build instance
- IAM permissions for EC2, EBS, and AMI operations

### vSphere Requirements

- vCenter Server access with appropriate permissions
- Datastore with sufficient space (~50GB)
- Network with DHCP or static IP configuration
- Content Library for template storage

## Usage

### Building AWS AMIs

```bash
# Set AWS credentials
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# Build Rocky Linux 9 AMI
packer build \
  -var "rocky_version=9" \
  -var "aws_region=us-east-1" \
  -var "instance_type=t3.medium" \
  packer/rocky-aws.pkr.hcl

# Build Rocky Linux 10 AMI
packer build \
  -var "rocky_version=10" \
  packer/rocky-aws.pkr.hcl
```

### Building vSphere Templates

```bash
# Build with variable file
packer build \
  -var-file="packer/variables.auto.pkrvars.hcl" \
  packer/rocky-vsphere.pkr.hcl

# Or pass variables directly
packer build \
  -var "vcenter_server=vcenter.example.com" \
  -var "vcenter_username=administrator@vsphere.local" \
  -var "vcenter_password=YourPassword" \
  -var "vcenter_datacenter=DC1" \
  -var "vcenter_cluster=Cluster1" \
  -var "vcenter_datastore=Datastore1" \
  -var "vcenter_network=VM Network" \
  -var "content_library_name=Templates" \
  packer/rocky-vsphere.pkr.hcl
```

## Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_ACCESS_KEY_ID` | AWS access key | - |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key | - |
| `AWS_DEFAULT_REGION` | AWS region | us-east-1 |
| `VCENTER_SERVER` | vCenter hostname | - |
| `VCENTER_USERNAME` | vCenter username | - |
| `VCENTER_PASSWORD` | vCenter password | - |

### Variable Files

Copy the example variable file and customize:

```bash
cp packer/variables.auto.pkrvars.hcl.example packer/variables.auto.pkrvars.hcl
```

#### AWS Variables

| Variable | Type | Description | Default |
|----------|------|-------------|---------|
| `rocky_version` | string | Rocky Linux version (9 or 10) | "9" |
| `aws_region` | string | Build region | "us-east-1" |
| `vpc_id` | string | VPC for build instance | "" (default VPC) |
| `subnet_id` | string | Subnet for build instance | "" (default) |
| `instance_type` | string | EC2 instance type | "t3.medium" |
| `root_volume_size` | number | Root volume size (GB) | 40 |
| `ami_regions` | list | Regions to copy AMI to | [] |
| `ami_users` | list | Account IDs to share AMI | [] |

#### vSphere Variables

| Variable | Type | Description | Default |
|----------|------|-------------|---------|
| `vcenter_server` | string | vCenter hostname | - |
| `vcenter_username` | string | vCenter username | - |
| `vcenter_password` | string | vCenter password | - |
| `vcenter_datacenter` | string | Datacenter name | - |
| `vcenter_cluster` | string | Cluster name | - |
| `vcenter_datastore` | string | Datastore name | - |
| `vcenter_network` | string | Network name | - |
| `content_library_name` | string | Content library name | - |
| `vm_cpu_count` | number | vCPUs | 2 |
| `vm_memory` | number | Memory (MB) | 4096 |
| `vm_disk_size` | number | Disk size (MB) | 40960 |

## Validation and Testing

### Running InSpec Compliance Tests

```bash
# Test a running instance
inspec exec inspec/cis-benchmark -t ssh://user@hostname -i ~/.ssh/key.pem

# Test with sudo
inspec exec inspec/cis-benchmark -t ssh://user@hostname -i ~/.ssh/key.pem --sudo

# Generate HTML report
inspec exec inspec/cis-benchmark -t ssh://user@hostname \
  --reporter html:reports/compliance.html
```

### Validating Packer Templates

```bash
# Validate AWS template
packer validate packer/rocky-aws.pkr.hcl

# Validate vSphere template
packer validate -var-file="packer/variables.auto.pkrvars.hcl" packer/rocky-vsphere.pkr.hcl
```

### Ansible Syntax Check

```bash
cd ansible
ansible-playbook playbook.yml --syntax-check
ansible-lint playbook.yml
```

## CI/CD Pipeline

The project includes GitHub Actions workflows for automated image building:

### Workflow Overview

```
Trigger (push/schedule/manual)
    |
    v
+-------------------+
|  Validate         |  - Packer validate
|  Templates        |  - Ansible lint
+-------------------+
    |
    v
+-------------------+
|  Build Images     |  - AWS AMI
|                   |  - vSphere template
+-------------------+
    |
    v
+-------------------+
|  Compliance       |  - InSpec tests
|  Testing          |  - CIS benchmarks
+-------------------+
    |
    v
+-------------------+
|  Publish          |  - Tag release
|  Artifacts        |  - Update manifests
+-------------------+
```

### Triggering Builds

- **Automatic**: Triggered on pushes to `main` branch
- **Scheduled**: Weekly builds for security updates
- **Manual**: Workflow dispatch from GitHub Actions UI

## Project Structure

```
standard-linux-image/
├── packer/
│   ├── rocky-aws.pkr.hcl        # AWS AMI builder
│   ├── rocky-vsphere.pkr.hcl    # vSphere template builder
│   ├── variables.pkr.hcl        # Shared variables
│   ├── plugins.pkr.hcl          # Plugin requirements
│   └── http/                    # Kickstart files
│       ├── ks-rocky9.cfg
│       └── ks-rocky10.cfg
├── ansible/
│   ├── playbook.yml             # Main playbook
│   ├── ansible.cfg              # Ansible configuration
│   ├── inventory/               # Inventory files
│   └── roles/
│       ├── base/                # Base OS configuration
│       ├── cloud-init/          # Cloud-init setup
│       ├── hardening/           # CIS hardening
│       ├── vsphere/             # vSphere-specific
│       └── aws/                 # AWS-specific
├── inspec/
│   └── cis-benchmark/           # Compliance profiles
├── scripts/
│   └── cleanup.sh               # Image cleanup
├── .github/
│   └── workflows/               # CI/CD pipelines
└── README.md
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:

- Setting up your development environment
- Code style and commit message conventions
- Submitting pull requests
- Running tests locally

## Version History

Template versions follow CalVer format: `YYYY.MM.PATCH`

- **YYYY.MM**: Year and month of base OS security patches
- **PATCH**: Incremental changes within the month

See [Releases](https://github.com/YOUR_ORG/standard-linux-image/releases) for version history.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [Packer Documentation](https://developer.hashicorp.com/packer/docs)
- [Ansible Documentation](https://docs.ansible.com/)
- [InSpec Documentation](https://docs.chef.io/inspec/)
- [Cloud-init Documentation](https://cloudinit.readthedocs.io/)
