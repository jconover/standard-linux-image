packer {
  required_version = ">= 1.9.0"
  required_plugins {
    vsphere = {
      version = ">= 1.2.0"
      source  = "github.com/hashicorp/vsphere"
    }
    ansible = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/ansible"
    }
  }
}

# =============================================================================
# Variables - vSphere Connection
# =============================================================================

variable "vcenter_server" {
  type        = string
  description = "vCenter Server hostname or IP address"
}

variable "vcenter_username" {
  type        = string
  description = "vCenter Server username"
}

variable "vcenter_password" {
  type        = string
  description = "vCenter Server password"
  sensitive   = true
}

variable "vcenter_insecure_connection" {
  type        = bool
  description = "Allow insecure connection to vCenter"
  default     = false
}

# =============================================================================
# Variables - vSphere Infrastructure
# =============================================================================

variable "vcenter_datacenter" {
  type        = string
  description = "vSphere datacenter name"
}

variable "vcenter_cluster" {
  type        = string
  description = "vSphere cluster name"
}

variable "vcenter_datastore" {
  type        = string
  description = "vSphere datastore name"
}

variable "vcenter_network" {
  type        = string
  description = "vSphere network name"
}

variable "vcenter_folder" {
  type        = string
  description = "vSphere folder for VM placement"
  default     = ""
}

variable "vcenter_resource_pool" {
  type        = string
  description = "vSphere resource pool"
  default     = ""
}

# =============================================================================
# Variables - Content Library
# =============================================================================

variable "content_library_name" {
  type        = string
  description = "Name of the content library to store the template"
}

variable "content_library_ovf" {
  type        = bool
  description = "Export as OVF to content library"
  default     = true
}

variable "content_library_destroy" {
  type        = bool
  description = "Destroy the VM after exporting to content library"
  default     = true
}

variable "content_library_overwrite" {
  type        = bool
  description = "Overwrite existing item in content library"
  default     = true
}

# =============================================================================
# Variables - Rocky Linux Version
# =============================================================================

variable "rocky_version" {
  type        = string
  description = "Rocky Linux major version (9 or 10)"
  default     = "9"

  validation {
    condition     = contains(["9", "10"], var.rocky_version)
    error_message = "Rocky Linux version must be 9 or 10."
  }
}

variable "rocky_iso_url" {
  type        = string
  description = "URL to Rocky Linux ISO"
  default     = ""
}

variable "rocky_iso_checksum" {
  type        = string
  description = "Checksum for Rocky Linux ISO"
  default     = ""
}

# =============================================================================
# Variables - VM Hardware Configuration
# =============================================================================

variable "vm_cpu_count" {
  type        = number
  description = "Number of vCPUs"
  default     = 2
}

variable "vm_memory" {
  type        = number
  description = "Memory in MB"
  default     = 4096
}

variable "vm_disk_size" {
  type        = number
  description = "Disk size in MB"
  default     = 40960
}

variable "vm_guest_os_type" {
  type        = string
  description = "vSphere guest OS type"
  default     = "rockylinux_64Guest"
}

# =============================================================================
# Variables - Build Configuration
# =============================================================================

variable "ssh_username" {
  type        = string
  description = "SSH username for provisioning"
  default     = "root"
}

variable "ssh_password" {
  type        = string
  description = "SSH password for provisioning"
  sensitive   = true
}

variable "ssh_timeout" {
  type        = string
  description = "SSH connection timeout"
  default     = "30m"
}

variable "http_directory" {
  type        = string
  description = "Directory containing kickstart files"
  default     = "http"
}

variable "boot_wait" {
  type        = string
  description = "Time to wait before typing boot command"
  default     = "5s"
}

# =============================================================================
# Locals
# =============================================================================

locals {
  build_timestamp = formatdate("YYYYMMDD", timestamp())
  vm_name         = "rocky-${var.rocky_version}-base-${local.build_timestamp}"

  # ISO URLs for Rocky Linux versions (defaults if not provided)
  iso_urls = {
    "9"  = var.rocky_iso_url != "" ? var.rocky_iso_url : "https://download.rockylinux.org/pub/rocky/9/isos/x86_64/Rocky-9-latest-x86_64-dvd.iso"
    "10" = var.rocky_iso_url != "" ? var.rocky_iso_url : "https://download.rockylinux.org/pub/rocky/10/isos/x86_64/Rocky-10-latest-x86_64-dvd.iso"
  }

  # Boot command for UEFI kickstart installation
  boot_command = [
    "<up>",
    "e",
    "<down><down><end>",
    " inst.text inst.ks=http://{{ .HTTPIP }}:{{ .HTTPPort }}/ks-rocky${var.rocky_version}.cfg",
    "<leftCtrlOn>x<leftCtrlOff>"
  ]
}

# =============================================================================
# Source - vSphere ISO Builder
# =============================================================================

source "vsphere-iso" "rocky" {
  # vCenter Connection
  vcenter_server      = var.vcenter_server
  username            = var.vcenter_username
  password            = var.vcenter_password
  insecure_connection = var.vcenter_insecure_connection

  # vSphere Infrastructure
  datacenter    = var.vcenter_datacenter
  cluster       = var.vcenter_cluster
  datastore     = var.vcenter_datastore
  folder        = var.vcenter_folder
  resource_pool = var.vcenter_resource_pool

  # VM Configuration
  vm_name              = local.vm_name
  guest_os_type        = var.vm_guest_os_type
  CPUs                 = var.vm_cpu_count
  RAM                  = var.vm_memory
  RAM_reserve_all      = false
  firmware             = "efi"

  # Enable EFI Secure Boot
  vm_advanced_options = {
    "uefi.secureBoot.enabled" = "TRUE"
  }

  # Disk Configuration
  disk_controller_type = ["pvscsi"]
  storage {
    disk_size             = var.vm_disk_size
    disk_thin_provisioned = true
  }

  # Network Configuration
  network_adapters {
    network      = var.vcenter_network
    network_card = "vmxnet3"
  }

  # ISO Configuration
  iso_url      = local.iso_urls[var.rocky_version]
  iso_checksum = var.rocky_iso_checksum != "" ? var.rocky_iso_checksum : "none"

  # Boot Configuration
  boot_command = local.boot_command
  boot_wait    = var.boot_wait
  http_directory = var.http_directory

  # SSH Configuration
  ssh_username = var.ssh_username
  ssh_password = var.ssh_password
  ssh_timeout  = var.ssh_timeout

  # Convert to Template
  convert_to_template = true

  # Content Library Destination
  content_library_destination {
    library     = var.content_library_name
    name        = local.vm_name
    ovf         = var.content_library_ovf
    destroy     = var.content_library_destroy
    overwrite   = var.content_library_overwrite
    description = "Rocky Linux ${var.rocky_version} base template built on ${local.build_timestamp}"
  }

  # Notes for the VM/Template
  notes = "Rocky Linux ${var.rocky_version} base template\nBuilt: ${local.build_timestamp}\nPacker managed - Do not modify directly"
}

# =============================================================================
# Build
# =============================================================================

build {
  name    = "rocky-linux"
  sources = ["source.vsphere-iso.rocky"]

  # Ansible Provisioner - Main Configuration
  provisioner "ansible" {
    playbook_file = "../ansible/playbook.yml"
    user          = var.ssh_username
    use_proxy     = false

    extra_arguments = [
      "-e", "ansible_ssh_pass=${var.ssh_password}",
      "-e", "rocky_version=${var.rocky_version}",
      "--scp-extra-args", "'-O'"
    ]

    ansible_env_vars = [
      "ANSIBLE_HOST_KEY_CHECKING=False",
      "ANSIBLE_SSH_ARGS='-o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=/dev/null'"
    ]
  }

  # Shell Provisioner - Cleanup Script
  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; sudo {{ .Path }}"
    scripts = [
      "scripts/cleanup.sh"
    ]
    expect_disconnect = true
  }

  # Post-processor for manifest (optional)
  post-processor "manifest" {
    output     = "manifest-rocky-${var.rocky_version}.json"
    strip_path = true
    custom_data = {
      rocky_version   = var.rocky_version
      build_timestamp = local.build_timestamp
      vm_name         = local.vm_name
    }
  }
}
