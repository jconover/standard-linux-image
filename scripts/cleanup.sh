#!/bin/bash
# Cleanup script for Packer image building
# Prepares the image for deployment by removing temporary files and sensitive data

set -e

# Configuration
ZERO_FREE_SPACE="${ZERO_FREE_SPACE:-false}"

echo "=== Starting cleanup process ==="

# Clear package manager cache
echo "Clearing package manager cache..."
if command -v dnf &> /dev/null; then
    dnf clean all
    rm -rf /var/cache/dnf/*
elif command -v yum &> /dev/null; then
    yum clean all
    rm -rf /var/cache/yum/*
fi

# Remove temporary files
echo "Removing temporary files..."
rm -rf /tmp/*
rm -rf /var/tmp/*

# Clear log files (truncate, don't delete)
echo "Clearing log files..."
find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
find /var/log -type f -name "*.log.*" -delete
find /var/log -type f -name "*.gz" -delete
find /var/log -type f -name "*.old" -delete
truncate -s 0 /var/log/lastlog 2>/dev/null || true
truncate -s 0 /var/log/wtmp 2>/dev/null || true
truncate -s 0 /var/log/btmp 2>/dev/null || true

# Clear audit logs
truncate -s 0 /var/log/audit/audit.log 2>/dev/null || true

# Remove kickstart files
echo "Removing kickstart files..."
rm -f /root/anaconda-ks.cfg
rm -f /root/original-ks.cfg
rm -f /root/ks-post.log

# Clear bash history for all users
echo "Clearing bash history..."
for user_home in /root /home/*; do
    if [ -d "$user_home" ]; then
        rm -f "$user_home/.bash_history"
        rm -f "$user_home/.viminfo"
        rm -f "$user_home/.lesshst"
    fi
done
unset HISTFILE
history -c

# Remove SSH host keys (will be regenerated on first boot)
echo "Removing SSH host keys..."
rm -f /etc/ssh/ssh_host_*

# Clear machine-id (will be regenerated on first boot)
echo "Clearing machine-id..."
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id

# Remove the packer user
echo "Removing packer user..."
if id packer &>/dev/null; then
    userdel -rf packer 2>/dev/null || true
fi
rm -f /etc/sudoers.d/packer

# Remove udev rules for persistent network naming
echo "Removing udev persistent network rules..."
rm -f /etc/udev/rules.d/70-persistent-net.rules
rm -f /etc/udev/rules.d/75-persistent-net-generator.rules

# Clear network configuration that might be system-specific
echo "Clearing network configuration..."
rm -f /etc/sysconfig/network-scripts/ifcfg-e*
# Keep loopback configuration

# Remove random seed
echo "Removing random seed..."
rm -f /var/lib/systemd/random-seed

# Remove DNF/YUM history
echo "Removing package manager history..."
rm -rf /var/lib/dnf/history*
rm -rf /var/lib/yum/history*

# Sync filesystem before zeroing
echo "Syncing filesystem..."
sync

# Zero out free space for better compression (optional)
if [ "$ZERO_FREE_SPACE" = "true" ]; then
    echo "Zeroing free space (this may take a while)..."

    # Zero root filesystem
    dd if=/dev/zero of=/EMPTY bs=1M 2>/dev/null || true
    rm -f /EMPTY

    # Zero boot filesystem
    dd if=/dev/zero of=/boot/EMPTY bs=1M 2>/dev/null || true
    rm -f /boot/EMPTY

    # Zero EFI filesystem
    dd if=/dev/zero of=/boot/efi/EMPTY bs=1M 2>/dev/null || true
    rm -f /boot/efi/EMPTY

    # Sync after zeroing
    sync
fi

# Clear swap
echo "Clearing swap..."
SWAP_DEVICE=$(swapon --show=NAME --noheadings | head -n1)
if [ -n "$SWAP_DEVICE" ]; then
    swapoff "$SWAP_DEVICE" 2>/dev/null || true
    dd if=/dev/zero of="$SWAP_DEVICE" bs=1M 2>/dev/null || true
    mkswap "$SWAP_DEVICE" 2>/dev/null || true
fi

# Final sync
sync

echo "=== Cleanup complete ==="
