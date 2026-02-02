# Changelog

All notable changes to the Standard Linux Image project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Calendar Versioning](https://calver.org/) with the format `YYYY.MM.PATCH`.

## [Unreleased]

### Added
- Nothing yet

### Changed
- Nothing yet

### Fixed
- Nothing yet

### Security
- Nothing yet

## [v2026.02.0] - 2026-02-02

### Added
- Initial release of Standard Linux Image
- Rocky Linux 9 and Rocky Linux 10 support
- vSphere template builds with VMware Tools integration
- AWS AMI builds with cloud-init configuration
- CIS Benchmark Level 1 hardening (Server profile)
- Ansible-based configuration management
  - Base role for common system configuration
  - Hardening role implementing security controls
  - Cloud-init role for instance initialization
  - vSphere role for VMware-specific configuration
  - AWS role for Amazon-specific configuration
- InSpec test suite for CIS benchmark compliance validation
- Goss test suite for runtime validation
- GitHub Actions CI/CD workflows
  - Automated image builds for vSphere and AWS
  - Security scanning and compliance testing
  - Release automation with notifications

### Changed
- Nothing yet (initial release)

### Fixed
- Nothing yet (initial release)

### Security
- Implemented CIS Benchmark Level 1 controls for Rocky Linux
- SSH hardening with secure cipher suites and key exchange algorithms
- Auditd configuration for security event logging
- Kernel parameter hardening via sysctl
- Filesystem permissions hardening
- PAM configuration for password policies
- Service hardening and disabling unnecessary services
- Firewall configuration with default deny policy

---

## Version Format

This project uses Calendar Versioning (CalVer):
- `YYYY` - Four-digit year
- `MM` - Two-digit month (zero-padded)
- `PATCH` - Incremental patch number within the month

Pre-release versions may include suffixes:
- `-rc1`, `-rc2`, etc. for release candidates
- `-beta1`, `-beta2`, etc. for beta releases

Example: `v2026.02.0`, `v2026.02.1-rc1`, `v2026.03.0-beta1`

## Links

[Unreleased]: https://github.com/OWNER/standard-linux-image/compare/v2026.02.0...HEAD
[v2026.02.0]: https://github.com/OWNER/standard-linux-image/releases/tag/v2026.02.0
