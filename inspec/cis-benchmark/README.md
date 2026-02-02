# CIS Rocky Linux 9/10 Benchmark InSpec Profile

## Overview

This InSpec profile validates compliance with the CIS (Center for Internet Security) Benchmark for Rocky Linux 9 and 10. It provides automated security validation for hardened Linux systems built from the standard-linux-image project.

The profile covers the following CIS benchmark sections:
- Initial Setup (filesystem, software updates, secure boot)
- Services (inetd, special purpose services, service clients)
- Network Configuration (network parameters, firewall, wireless)
- Logging and Auditing (configure logging, configure audit)
- Access, Authentication and Authorization (cron, SSH, PAM, user accounts)
- System Maintenance (file permissions, user and group settings)

## Requirements

- [InSpec](https://www.inspec.io/) version 4.0 or higher
- Target system running Rocky Linux 9 or 10
- SSH access to the target system (for remote scans)
- Appropriate privileges (root or sudo) on the target system

## Installation

Clone or download this profile:

```bash
git clone <repository-url>
cd inspec/cis-benchmark
```

Or use directly from the repository:

```bash
inspec exec https://github.com/<org>/standard-linux-image/inspec/cis-benchmark
```

## Usage

### Running Locally

To run the profile on the local system:

```bash
inspec exec /path/to/cis-benchmark --sudo
```

### Running Against a Remote Target

To run the profile against a remote system via SSH:

```bash
inspec exec /path/to/cis-benchmark -t ssh://user@hostname --sudo
```

With a specific SSH key:

```bash
inspec exec /path/to/cis-benchmark -t ssh://user@hostname -i ~/.ssh/id_rsa --sudo
```

### Running with Custom Inputs

Override default input values using a YAML file:

```bash
inspec exec /path/to/cis-benchmark --input-file inputs.yml --sudo
```

Or specify inputs directly on the command line:

```bash
inspec exec /path/to/cis-benchmark --input ssh_port=2222 --sudo
```

### Generating Reports

Generate an HTML report:

```bash
inspec exec /path/to/cis-benchmark --sudo --reporter html:report.html
```

Generate a JSON report:

```bash
inspec exec /path/to/cis-benchmark --sudo --reporter json:report.json
```

Generate multiple reports simultaneously:

```bash
inspec exec /path/to/cis-benchmark --sudo \
  --reporter cli json:report.json html:report.html
```

## Input Variables

The following input variables can be customized to match your organization's security policy:

| Input | Type | Default | Description |
|-------|------|---------|-------------|
| `ssh_port` | Numeric | 22 | SSH service port |
| `allowed_services` | Array | [sshd, chronyd, auditd, rsyslog] | Services allowed to be running |
| `ssh_client_alive_interval` | Numeric | 300 | SSH ClientAliveInterval (seconds) |
| `ssh_client_alive_count_max` | Numeric | 3 | SSH ClientAliveCountMax |
| `ssh_login_grace_time` | Numeric | 60 | SSH LoginGraceTime (seconds) |
| `ssh_max_auth_tries` | Numeric | 4 | SSH MaxAuthTries |
| `ssh_max_sessions` | Numeric | 10 | SSH MaxSessions |
| `password_max_days` | Numeric | 365 | Maximum password age (days) |
| `password_min_days` | Numeric | 1 | Minimum password age (days) |
| `password_warn_age` | Numeric | 7 | Password expiration warning (days) |
| `password_min_length` | Numeric | 14 | Minimum password length |
| `audit_log_max_size` | Numeric | 8 | Maximum audit log size (MB) |
| `allowed_system_accounts` | Array | [root] | System accounts allowed to have shells |
| `umask_default` | String | 027 | Default umask value |
| `banner_message_enabled` | Boolean | true | Display login banner |
| `disable_ipv6` | Boolean | false | Whether IPv6 should be disabled |
| `time_servers` | Array | [time.cloudflare.com, time.google.com] | Approved NTP servers |

### Example Input File

Create a file named `inputs.yml`:

```yaml
ssh_port: 2222
ssh_client_alive_interval: 600
allowed_services:
  - sshd
  - chronyd
  - auditd
  - rsyslog
  - docker
password_max_days: 90
password_min_length: 16
```

## Profile Structure

```
cis-benchmark/
├── inspec.yml          # Profile metadata and inputs
├── inspec.lock         # Dependency lock file
├── README.md           # This documentation
├── controls/           # InSpec control files
│   └── example.rb      # Example control (OS verification)
├── libraries/          # Custom InSpec resources
└── files/              # Supporting files
```

## Control Organization

Controls are organized by CIS benchmark section:

- `1_*.rb` - Initial Setup
- `2_*.rb` - Services
- `3_*.rb` - Network Configuration
- `4_*.rb` - Logging and Auditing
- `5_*.rb` - Access, Authentication and Authorization
- `6_*.rb` - System Maintenance

## Waiving Controls

To waive specific controls that don't apply to your environment, create a waiver file:

```yaml
# waivers.yml
cis-1.1.1.1:
  expiration_date: 2025-12-31
  justification: "cramfs is required for legacy application support"
  run: false

cis-5.2.18:
  justification: "Using certificate-based authentication instead"
  run: true  # Still runs but marks as waived
```

Apply waivers:

```bash
inspec exec /path/to/cis-benchmark --waiver-file waivers.yml --sudo
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add or modify controls
4. Test your changes
5. Submit a pull request

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [InSpec Documentation](https://docs.chef.io/inspec/)
- [InSpec Resources Reference](https://docs.chef.io/inspec/resources/)

## License

Apache-2.0

## Maintainer

Your Organization
