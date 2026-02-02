# Goss Health Checks

Goss is a YAML-based serverspec alternative for validating server configurations.

## Installing Goss

### Linux (AMD64)

```bash
curl -L https://github.com/goss-org/goss/releases/latest/download/goss-linux-amd64 -o /usr/local/bin/goss
chmod +rx /usr/local/bin/goss
```

### Linux (ARM64)

```bash
curl -L https://github.com/goss-org/goss/releases/latest/download/goss-linux-arm64 -o /usr/local/bin/goss
chmod +rx /usr/local/bin/goss
```

### Using Package Manager (if available)

```bash
# For systems with goss in repositories
dnf install goss
```

## Running Goss Validate

### Basic Validation

Run from the project root directory:

```bash
cd /path/to/standard-linux-image
goss -g goss/goss.yaml validate
```

### Verbose Output

```bash
goss -g goss/goss.yaml validate -f documentation
```

### With Retry (useful for services that may take time to start)

```bash
goss -g goss/goss.yaml validate --retry-timeout 30s --sleep 5s
```

## Generating Reports

### JSON Report

```bash
goss -g goss/goss.yaml validate -f json > goss-report.json
```

### JUnit XML Report (for CI/CD integration)

```bash
goss -g goss/goss.yaml validate -f junit > goss-report.xml
```

### TAP Report

```bash
goss -g goss/goss.yaml validate -f tap > goss-report.tap
```

### Documentation Format (human-readable)

```bash
goss -g goss/goss.yaml validate -f documentation
```

## File Structure

```
goss/
├── goss.yaml       # Main configuration (includes other files)
├── services.yaml   # Service health checks
├── packages.yaml   # Package verification
├── files.yaml      # Critical file checks
├── commands.yaml   # Command output checks
└── README.md       # This file
```

## Adding New Tests

### Auto-generate from current system state

```bash
# Add a service check
goss add service sshd

# Add a file check
goss add file /etc/passwd

# Add a package check
goss add package nginx

# Add a command check
goss add command "uname -r"
```

### Manual Addition

Edit the appropriate YAML file and add entries following the existing format.

## Integration with Packer

Add to your Packer build:

```hcl
provisioner "shell" {
  inline = [
    "curl -L https://github.com/goss-org/goss/releases/latest/download/goss-linux-amd64 -o /usr/local/bin/goss",
    "chmod +rx /usr/local/bin/goss"
  ]
}

provisioner "file" {
  source      = "goss/"
  destination = "/tmp/goss/"
}

provisioner "shell" {
  inline = [
    "cd /tmp && goss -g goss/goss.yaml validate"
  ]
}
```

## Exit Codes

- `0` - All tests passed
- `1` - One or more tests failed
- `2` - Error running goss (invalid YAML, etc.)
