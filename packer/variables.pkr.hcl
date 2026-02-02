# Rocky Linux Version
variable "rocky_version" {
  type        = string
  default     = "9"
  description = "Rocky Linux version"
}

# Common Variables
variable "ssh_username" {
  type        = string
  default     = "root"
  description = "SSH username for provisioning"
}

variable "ssh_timeout" {
  type        = string
  default     = "30m"
  description = "SSH connection timeout"
}

# vSphere Variables
variable "vcenter_server" {
  type        = string
  default     = ""
  description = "vCenter server hostname or IP address"
}

variable "vcenter_username" {
  type        = string
  default     = ""
  description = "vCenter username"
}

variable "vcenter_password" {
  type        = string
  default     = ""
  sensitive   = true
  description = "vCenter password"
}

variable "datacenter" {
  type        = string
  default     = ""
  description = "vSphere datacenter name"
}

variable "cluster" {
  type        = string
  default     = ""
  description = "vSphere cluster name"
}

variable "datastore" {
  type        = string
  default     = ""
  description = "vSphere datastore name"
}

variable "network" {
  type        = string
  default     = ""
  description = "vSphere network name"
}

variable "folder" {
  type        = string
  default     = ""
  description = "vSphere folder path for the VM"
}

variable "content_library" {
  type        = string
  default     = ""
  description = "vSphere content library name for template storage"
}

# AWS Variables
variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region for building the AMI"
}

variable "vpc_id" {
  type        = string
  default     = ""
  description = "VPC ID for the build instance"
}

variable "subnet_id" {
  type        = string
  default     = ""
  description = "Subnet ID for the build instance"
}

variable "instance_type" {
  type        = string
  default     = "t3.medium"
  description = "EC2 instance type for building the AMI"
}

variable "ami_regions" {
  type        = list(string)
  default     = []
  description = "List of regions to copy the AMI to"
}

variable "ami_users" {
  type        = list(string)
  default     = []
  description = "List of AWS account IDs to share the AMI with"
}

# Build Metadata
variable "build_version" {
  type        = string
  default     = "1.0.0"
  description = "Version string for the build"
}
