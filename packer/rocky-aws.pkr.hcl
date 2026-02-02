# Packer HCL template for Rocky Linux on AWS
# Supports Rocky Linux 9 and 10

packer {
  required_plugins {
    amazon = {
      version = ">= 1.2.0"
      source  = "github.com/hashicorp/amazon"
    }
    ansible = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/ansible"
    }
  }
}

# ============================================================================
# Variables
# ============================================================================

variable "rocky_version" {
  type        = string
  description = "Rocky Linux major version (9 or 10)"
  default     = "9"

  validation {
    condition     = contains(["9", "10"], var.rocky_version)
    error_message = "Rocky version must be either '9' or '10'."
  }
}

variable "aws_region" {
  type        = string
  description = "AWS region to build the AMI in"
  default     = "us-east-1"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID where the build instance will be launched"
  default     = ""
}

variable "subnet_id" {
  type        = string
  description = "Subnet ID where the build instance will be launched"
  default     = ""
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type to use for the build"
  default     = "t3.medium"
}

variable "ami_regions" {
  type        = list(string)
  description = "List of regions to copy the AMI to"
  default     = []
}

variable "ami_users" {
  type        = list(string)
  description = "List of AWS account IDs to share the AMI with"
  default     = []
}

variable "ssh_username" {
  type        = string
  description = "SSH username for connecting to the instance"
  default     = "rocky"
}

variable "root_volume_size" {
  type        = number
  description = "Size of the root volume in GB"
  default     = 40
}

# ============================================================================
# Locals
# ============================================================================

locals {
  timestamp  = formatdate("YYYYMMDD", timestamp())
  ami_name   = "rocky-${var.rocky_version}-base-${local.timestamp}"
  ami_description = "Rocky Linux ${var.rocky_version} base image built on ${local.timestamp}"

  # Common tags for the AMI
  common_tags = {
    Name        = local.ami_name
    Version     = var.rocky_version
    BuildDate   = local.timestamp
    OS          = "Rocky Linux"
    OSVersion   = var.rocky_version
    Builder     = "Packer"
    Environment = "base"
  }
}

# ============================================================================
# Source: Amazon EBS
# ============================================================================

source "amazon-ebs" "rocky" {
  ami_name        = local.ami_name
  ami_description = local.ami_description
  instance_type   = var.instance_type
  region          = var.aws_region

  # VPC/Subnet configuration (optional - uses default if not specified)
  vpc_id    = var.vpc_id != "" ? var.vpc_id : null
  subnet_id = var.subnet_id != "" ? var.subnet_id : null

  # Source AMI filter for official Rocky Linux AMIs
  source_ami_filter {
    filters = {
      name                = "Rocky-${var.rocky_version}-EC2-Base-${var.rocky_version}.*-x86_64-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
      architecture        = "x86_64"
    }
    owners      = ["792107900819"]  # Official Rocky Linux AWS account
    most_recent = true
  }

  # SSH configuration
  ssh_username         = var.ssh_username
  ssh_timeout          = "10m"
  ssh_interface        = "public_ip"

  # Root volume configuration
  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = var.root_volume_size
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  # Enable ENA support
  ena_support = true

  # Multi-region copy
  ami_regions = var.ami_regions

  # AMI sharing
  ami_users = var.ami_users

  # Tags
  tags = local.common_tags

  run_tags = merge(local.common_tags, {
    Name = "packer-builder-${local.ami_name}"
  })

  snapshot_tags = local.common_tags
}

# ============================================================================
# Build
# ============================================================================

build {
  name    = "rocky-linux"
  sources = ["source.amazon-ebs.rocky"]

  # Ansible provisioner for configuration management
  provisioner "ansible" {
    playbook_file = "${path.root}/../ansible/playbook.yml"
    user          = var.ssh_username
    use_proxy     = false

    extra_arguments = [
      "--extra-vars", "rocky_version=${var.rocky_version}",
      "--extra-vars", "ansible_python_interpreter=/usr/bin/python3"
    ]

    ansible_env_vars = [
      "ANSIBLE_HOST_KEY_CHECKING=False",
      "ANSIBLE_SSH_ARGS='-o ForwardAgent=yes -o ControlMaster=auto -o ControlPersist=60s'"
    ]
  }

  # Shell provisioner for cleanup
  provisioner "shell" {
    inline = [
      "# Clean up cloud-init",
      "sudo cloud-init clean --logs --seed",

      "# Clean DNF cache",
      "sudo dnf clean all",
      "sudo rm -rf /var/cache/dnf/*",

      "# Remove SSH host keys (regenerated on first boot)",
      "sudo rm -f /etc/ssh/ssh_host_*",

      "# Clear machine-id (regenerated on first boot)",
      "sudo truncate -s 0 /etc/machine-id",

      "# Remove temporary files",
      "sudo rm -rf /tmp/*",
      "sudo rm -rf /var/tmp/*",

      "# Clear shell history",
      "sudo rm -f /root/.bash_history",
      "rm -f ~/.bash_history",
      "history -c",

      "# Clear logs",
      "sudo journalctl --vacuum-time=1s",
      "sudo find /var/log -type f -exec truncate -s 0 {} \\;",

      "# Sync filesystem",
      "sync"
    ]
    execute_command = "chmod +x {{ .Path }}; {{ .Vars }} bash {{ .Path }}"
  }

  # Post-processor to create manifest
  post-processor "manifest" {
    output     = "manifest-rocky-${var.rocky_version}.json"
    strip_path = true
    custom_data = {
      rocky_version = var.rocky_version
      build_date    = local.timestamp
      ami_name      = local.ami_name
    }
  }
}
