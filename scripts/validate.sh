#!/bin/bash
# Validation script for Packer images
# Runs basic checks to ensure the image is ready for deployment

set -e

ERRORS=0
WARNINGS=0

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ERRORS=$((ERRORS + 1))
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    WARNINGS=$((WARNINGS + 1))
}

info() {
    echo -e "[INFO] $1"
}

echo "=========================================="
echo "  Image Validation Script"
echo "=========================================="
echo ""

# System Information
info "OS: $(cat /etc/redhat-release 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2)"
info "Kernel: $(uname -r)"
info "Architecture: $(uname -m)"
echo ""

echo "--- Basic System Checks ---"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    pass "Running as root"
else
    warn "Not running as root - some checks may fail"
fi

# Check bootloader
if [ -d /sys/firmware/efi ]; then
    pass "UEFI boot mode detected"
else
    warn "BIOS boot mode detected (expected UEFI)"
fi

# Check filesystem type for root
ROOT_FS=$(df -T / | tail -1 | awk '{print $2}')
if [ "$ROOT_FS" = "xfs" ]; then
    pass "Root filesystem is XFS"
else
    warn "Root filesystem is $ROOT_FS (expected XFS)"
fi

# Check LVM
if pvs 2>/dev/null | grep -q pv; then
    pass "LVM is configured"
else
    warn "LVM not detected"
fi

echo ""
echo "--- Security Checks ---"

# Check if packer user exists (should be removed)
if id packer &>/dev/null; then
    fail "Packer user still exists (should be removed)"
else
    pass "Packer user removed"
fi

# Check if SSH host keys exist (should be removed for templating)
if ls /etc/ssh/ssh_host_* 1>/dev/null 2>&1; then
    warn "SSH host keys exist (may need regeneration on first boot)"
else
    pass "SSH host keys removed (will regenerate on first boot)"
fi

# Check machine-id
MACHINE_ID=$(cat /etc/machine-id 2>/dev/null)
if [ -z "$MACHINE_ID" ] || [ "$MACHINE_ID" = "" ]; then
    pass "Machine-id is empty (will regenerate on first boot)"
else
    warn "Machine-id is set: $MACHINE_ID"
fi

# Check SELinux status
if command -v getenforce &>/dev/null; then
    SELINUX_STATUS=$(getenforce)
    if [ "$SELINUX_STATUS" = "Enforcing" ]; then
        pass "SELinux is enforcing"
    elif [ "$SELINUX_STATUS" = "Permissive" ]; then
        warn "SELinux is permissive (expected enforcing)"
    else
        warn "SELinux is disabled"
    fi
else
    warn "SELinux tools not found"
fi

# Check firewall
if systemctl is-active firewalld &>/dev/null; then
    pass "Firewalld is active"
else
    warn "Firewalld is not active"
fi

echo ""
echo "--- Service Checks ---"

# Check SSH
if systemctl is-enabled sshd &>/dev/null; then
    pass "SSH service is enabled"
else
    fail "SSH service is not enabled"
fi

# Check for unwanted services
for service in cloud-init cloud-init-local cloud-config cloud-final; do
    if systemctl is-enabled "$service" &>/dev/null; then
        warn "$service is enabled (may not be desired)"
    fi
done

echo ""
echo "--- Disk Space Checks ---"

# Check root filesystem usage
ROOT_USAGE=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$ROOT_USAGE" -lt 50 ]; then
    pass "Root filesystem usage: ${ROOT_USAGE}%"
elif [ "$ROOT_USAGE" -lt 80 ]; then
    warn "Root filesystem usage: ${ROOT_USAGE}%"
else
    fail "Root filesystem usage critical: ${ROOT_USAGE}%"
fi

# Check /boot usage
BOOT_USAGE=$(df /boot | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$BOOT_USAGE" -lt 50 ]; then
    pass "Boot filesystem usage: ${BOOT_USAGE}%"
else
    warn "Boot filesystem usage: ${BOOT_USAGE}%"
fi

echo ""
echo "--- Network Checks ---"

# Check network configuration
if [ -f /etc/sysconfig/network-scripts/ifcfg-lo ] || [ -d /etc/NetworkManager/system-connections ]; then
    pass "Network configuration present"
else
    warn "Network configuration may need review"
fi

# Check if DHCP is configured (basic check)
if grep -rq "BOOTPROTO=dhcp\|method=auto" /etc/sysconfig/network-scripts/ /etc/NetworkManager/ 2>/dev/null; then
    pass "DHCP appears configured"
else
    info "Static IP or no network configuration found"
fi

echo ""
echo "--- Package Checks ---"

# Check for package manager
if command -v dnf &>/dev/null; then
    pass "DNF package manager available"
    DNF_VERSION=$(dnf --version 2>/dev/null | head -1)
    info "DNF version: $DNF_VERSION"
else
    fail "DNF package manager not found"
fi

# Check for required packages
for pkg in openssh-server sudo curl; do
    if rpm -q "$pkg" &>/dev/null; then
        pass "Package $pkg is installed"
    else
        fail "Package $pkg is NOT installed"
    fi
done

echo ""
echo "--- Cleanup Checks ---"

# Check for leftover temporary files
TMP_COUNT=$(find /tmp -mindepth 1 2>/dev/null | wc -l)
if [ "$TMP_COUNT" -eq 0 ]; then
    pass "/tmp is clean"
else
    warn "/tmp contains $TMP_COUNT items"
fi

# Check for bash history
if [ -f /root/.bash_history ]; then
    HISTORY_SIZE=$(wc -l < /root/.bash_history)
    if [ "$HISTORY_SIZE" -gt 0 ]; then
        warn "Root bash history exists ($HISTORY_SIZE lines)"
    else
        pass "Root bash history is empty"
    fi
else
    pass "No root bash history file"
fi

# Check for kickstart files
if [ -f /root/anaconda-ks.cfg ]; then
    warn "Kickstart file exists at /root/anaconda-ks.cfg"
else
    pass "Kickstart files cleaned up"
fi

echo ""
echo "=========================================="
echo "  Validation Summary"
echo "=========================================="
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}All checks passed!${NC}"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}Validation completed with $WARNINGS warning(s)${NC}"
    exit 0
else
    echo -e "${RED}Validation failed with $ERRORS error(s) and $WARNINGS warning(s)${NC}"
    exit 1
fi
