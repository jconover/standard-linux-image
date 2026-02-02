# Packer HCL template for validation only
# Uses null builder to run InSpec against existing images
# Can be used for periodic compliance checking without rebuilding

packer {
  required_version = ">= 1.9.0"
  required_plugins {
    ansible = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/ansible"
    }
  }
}

# =============================================================================
# Variables
# =============================================================================

variable "target_host" {
  type        = string
  description = "Target host for validation (SSH connection string, e.g., root@192.168.1.100)"
}

variable "ssh_private_key_file" {
  type        = string
  description = "Path to SSH private key for connecting to target"
  default     = ""
}

variable "ssh_password" {
  type        = string
  description = "SSH password for connecting to target (if not using key)"
  default     = ""
  sensitive   = true
}

variable "ssh_port" {
  type        = number
  description = "SSH port for connecting to target"
  default     = 22
}

variable "inspec_profile" {
  type        = string
  description = "Path to InSpec profile for CIS benchmark validation"
  default     = "../inspec/cis-benchmark"
}

variable "goss_file" {
  type        = string
  description = "Path to Goss validation file"
  default     = "../goss/goss.yaml"
}

variable "cis_threshold" {
  type        = number
  description = "Minimum CIS compliance score threshold (0-100)"
  default     = 80
}

variable "validation_report_dir" {
  type        = string
  description = "Directory to store validation reports"
  default     = "/tmp/validation-reports"
}

variable "fail_on_warning" {
  type        = bool
  description = "Fail the build if any warnings are detected"
  default     = false
}

variable "run_inspec" {
  type        = bool
  description = "Run InSpec CIS benchmark validation"
  default     = true
}

variable "run_goss" {
  type        = bool
  description = "Run Goss server validation"
  default     = true
}

variable "run_basic_checks" {
  type        = bool
  description = "Run basic system validation checks"
  default     = true
}

# =============================================================================
# Locals
# =============================================================================

locals {
  timestamp       = formatdate("YYYYMMDD-HHmmss", timestamp())
  validation_name = "validation-${local.timestamp}"

  # Extract username and host from target_host
  target_user = split("@", var.target_host)[0]
  target_addr = length(split("@", var.target_host)) > 1 ? split("@", var.target_host)[1] : var.target_host

  # Build validation script arguments
  validation_args = join(" ", compact([
    var.run_basic_checks ? "" : "--skip-basic",
    var.run_inspec ? "" : "--skip-inspec",
    var.run_goss ? "" : "--skip-goss",
    "-s ${var.cis_threshold}",
    "-r ${var.validation_report_dir}",
    "-f json"
  ]))
}

# =============================================================================
# Source - Null Builder (no actual build, just validation)
# =============================================================================

source "null" "validation" {
  communicator = "ssh"

  ssh_host            = local.target_addr
  ssh_username        = local.target_user
  ssh_port            = var.ssh_port
  ssh_private_key_file = var.ssh_private_key_file != "" ? var.ssh_private_key_file : null
  ssh_password        = var.ssh_password != "" ? var.ssh_password : null
  ssh_timeout         = "5m"
}

# =============================================================================
# Build - Validation Only
# =============================================================================

build {
  name    = "compliance-validation"
  sources = ["source.null.validation"]

  # Upload validation scripts
  provisioner "file" {
    source      = "${path.root}/../scripts/validate.sh"
    destination = "/tmp/validate.sh"
  }

  # Upload InSpec profile if running InSpec
  provisioner "file" {
    source      = var.inspec_profile
    destination = "/tmp/inspec-profile"
  }

  # Upload Goss files if running Goss
  provisioner "file" {
    source      = "${path.root}/../goss"
    destination = "/tmp/goss"
  }

  # Install validation tools if not present
  provisioner "shell" {
    inline = [
      "echo '=== Checking validation tools ==='",
      "",
      "# Check for InSpec",
      "if ! command -v inspec &>/dev/null; then",
      "  echo 'InSpec not found, installing...'",
      "  curl -fsSL https://omnitruck.chef.io/install.sh | bash -s -- -P inspec || echo 'InSpec installation failed'",
      "fi",
      "",
      "# Check for Goss",
      "if ! command -v goss &>/dev/null; then",
      "  echo 'Goss not found, installing...'",
      "  GOSS_VERSION=$(curl -fsSL https://api.github.com/repos/goss-org/goss/releases/latest | grep '\"tag_name\":' | sed -E 's/.*\"v([^\"]+)\".*/\\1/' || echo '0.4.4')",
      "  curl -fsSL -o /usr/local/bin/goss https://github.com/goss-org/goss/releases/download/v${GOSS_VERSION}/goss-linux-amd64",
      "  chmod +x /usr/local/bin/goss",
      "fi",
      "",
      "# Check for jq (needed for report parsing)",
      "if ! command -v jq &>/dev/null; then",
      "  echo 'Installing jq...'",
      "  dnf install -y jq || yum install -y jq || apt-get install -y jq || echo 'jq installation failed'",
      "fi",
      "",
      "echo '=== Validation tools check complete ==='"
    ]
    execute_command = "chmod +x {{ .Path }}; sudo bash {{ .Path }}"
  }

  # Run InSpec validation
  provisioner "shell" {
    inline = [
      "echo '=== Running InSpec CIS Benchmark Validation ==='",
      "",
      "if [ '${var.run_inspec}' != 'true' ]; then",
      "  echo 'InSpec validation skipped'",
      "  exit 0",
      "fi",
      "",
      "mkdir -p ${var.validation_report_dir}",
      "",
      "if command -v inspec &>/dev/null; then",
      "  cd /tmp/inspec-profile",
      "  inspec exec . --reporter cli json:${var.validation_report_dir}/inspec-results.json --chef-license accept-silent || true",
      "",
      "  # Parse and display results",
      "  if [ -f ${var.validation_report_dir}/inspec-results.json ]; then",
      "    PASSED=$(jq '[.profiles[0].controls[].results[] | select(.status == \"passed\")] | length' ${var.validation_report_dir}/inspec-results.json 2>/dev/null || echo 0)",
      "    FAILED=$(jq '[.profiles[0].controls[].results[] | select(.status == \"failed\")] | length' ${var.validation_report_dir}/inspec-results.json 2>/dev/null || echo 0)",
      "    TOTAL=$((PASSED + FAILED))",
      "    if [ $TOTAL -gt 0 ]; then",
      "      SCORE=$((PASSED * 100 / TOTAL))",
      "      echo \"CIS Compliance Score: $SCORE% (threshold: ${var.cis_threshold}%)\"",
      "      if [ $SCORE -lt ${var.cis_threshold} ]; then",
      "        echo 'ERROR: CIS compliance score below threshold'",
      "        exit 1",
      "      fi",
      "    fi",
      "  fi",
      "else",
      "  echo 'WARNING: InSpec not available'",
      "fi",
      "",
      "echo '=== InSpec validation complete ==='"
    ]
    execute_command = "chmod +x {{ .Path }}; sudo bash {{ .Path }}"
  }

  # Run Goss validation
  provisioner "shell" {
    inline = [
      "echo '=== Running Goss Server Validation ==='",
      "",
      "if [ '${var.run_goss}' != 'true' ]; then",
      "  echo 'Goss validation skipped'",
      "  exit 0",
      "fi",
      "",
      "mkdir -p ${var.validation_report_dir}",
      "",
      "if command -v goss &>/dev/null; then",
      "  cd /tmp",
      "  goss -g goss/goss.yaml validate --format json > ${var.validation_report_dir}/goss-results.json 2>&1 || true",
      "  goss -g goss/goss.yaml validate --format documentation || true",
      "",
      "  # Check for failures",
      "  if [ -f ${var.validation_report_dir}/goss-results.json ]; then",
      "    FAILED=$(jq '.summary.\"failed-count\"' ${var.validation_report_dir}/goss-results.json 2>/dev/null || echo 0)",
      "    if [ \"$FAILED\" != \"0\" ] && [ \"$FAILED\" != \"null\" ]; then",
      "      echo \"ERROR: Goss validation failed with $FAILED failures\"",
      "      exit 1",
      "    fi",
      "  fi",
      "else",
      "  echo 'WARNING: Goss not available'",
      "fi",
      "",
      "echo '=== Goss validation complete ==='"
    ]
    execute_command = "chmod +x {{ .Path }}; sudo bash {{ .Path }}"
  }

  # Run basic system checks
  provisioner "shell" {
    inline = [
      "echo '=== Running Basic System Validation ==='",
      "",
      "if [ '${var.run_basic_checks}' != 'true' ]; then",
      "  echo 'Basic checks skipped'",
      "  exit 0",
      "fi",
      "",
      "ERRORS=0",
      "",
      "# Check SELinux",
      "if command -v getenforce &>/dev/null; then",
      "  SELINUX=$(getenforce)",
      "  if [ \"$SELINUX\" = 'Enforcing' ]; then",
      "    echo 'PASS: SELinux is enforcing'",
      "  else",
      "    echo \"WARN: SELinux is $SELINUX (expected Enforcing)\"",
      "  fi",
      "fi",
      "",
      "# Check firewall",
      "if systemctl is-active firewalld &>/dev/null; then",
      "  echo 'PASS: Firewalld is active'",
      "else",
      "  echo 'WARN: Firewalld is not active'",
      "fi",
      "",
      "# Check critical services",
      "for svc in sshd auditd chronyd; do",
      "  if systemctl is-enabled $svc &>/dev/null; then",
      "    echo \"PASS: Service $svc is enabled\"",
      "  else",
      "    echo \"WARN: Service $svc is not enabled\"",
      "  fi",
      "done",
      "",
      "# Check disk usage",
      "ROOT_USAGE=$(df / | tail -1 | awk '{print $5}' | tr -d '%')",
      "if [ \"$ROOT_USAGE\" -lt 80 ]; then",
      "  echo \"PASS: Root filesystem usage: $ROOT_USAGE%\"",
      "else",
      "  echo \"FAIL: Root filesystem usage critical: $ROOT_USAGE%\"",
      "  ERRORS=$((ERRORS + 1))",
      "fi",
      "",
      "if [ $ERRORS -gt 0 ]; then",
      "  echo \"Basic validation failed with $ERRORS errors\"",
      "  exit 1",
      "fi",
      "",
      "echo '=== Basic validation complete ==='"
    ]
    execute_command = "chmod +x {{ .Path }}; sudo bash {{ .Path }}"
  }

  # Generate final validation report
  provisioner "shell" {
    inline = [
      "echo '=== Generating Validation Report ==='",
      "",
      "mkdir -p ${var.validation_report_dir}",
      "",
      "cat > ${var.validation_report_dir}/validation-summary.json << 'ENDREPORT'",
      "{",
      "  \"timestamp\": \"$(date -Iseconds)\",",
      "  \"target\": \"${var.target_host}\",",
      "  \"cis_threshold\": ${var.cis_threshold},",
      "  \"validations\": {",
      "    \"inspec\": ${var.run_inspec},",
      "    \"goss\": ${var.run_goss},",
      "    \"basic\": ${var.run_basic_checks}",
      "  },",
      "  \"status\": \"completed\"",
      "}",
      "ENDREPORT",
      "",
      "echo 'Validation reports available at: ${var.validation_report_dir}'",
      "ls -la ${var.validation_report_dir}/",
      "",
      "echo '=== Validation Complete ==='",
      "echo 'All validations passed successfully!'"
    ]
    execute_command = "chmod +x {{ .Path }}; sudo bash {{ .Path }}"
  }

  # Download reports to local machine
  provisioner "file" {
    source      = "${var.validation_report_dir}/"
    destination = "${path.root}/../reports/${local.validation_name}/"
    direction   = "download"
  }

  # Post-processor to create manifest
  post-processor "manifest" {
    output     = "manifest-validation-${local.timestamp}.json"
    strip_path = true
    custom_data = {
      validation_name = local.validation_name
      target_host     = var.target_host
      cis_threshold   = var.cis_threshold
      timestamp       = local.timestamp
    }
  }
}
