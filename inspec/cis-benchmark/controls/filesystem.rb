# frozen_string_literal: true

# CIS Benchmark - Section 1.1: Filesystem Configuration
# Controls for filesystem hardening and mount options

# -----------------------------------------------------------------------------
# 1.1.1.x - Disable Unused Filesystems
# -----------------------------------------------------------------------------

control 'cis-1.1.1.1' do
  impact 1.0
  title 'Ensure cramfs is disabled'
  desc 'The cramfs filesystem type is a compressed read-only Linux filesystem
        embedded in small footprint systems. A cramfs image can be used without
        having to first decompress the image.'
  desc 'rationale', 'Removing support for unneeded filesystem types reduces the
        local attack surface of the server.'
  desc 'check', 'Run the following commands and verify the output:
        modprobe -n -v cramfs | grep -E "(cramfs|install)"
        lsmod | grep cramfs'
  desc 'fix', 'Edit or create a file in the /etc/modprobe.d/ directory ending
        in .conf and add the following line:
        install cramfs /bin/true
        Run the following command to unload the cramfs module:
        rmmod cramfs'

  tag cis: 'cis-1.1.1.1'
  tag level: 1

  describe kernel_module('cramfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-1.1.1.2' do
  impact 1.0
  title 'Ensure freevxfs is disabled'
  desc 'The freevxfs filesystem type is a free version of the Veritas type
        filesystem. This is the primary filesystem type for HP-UX operating
        systems.'
  desc 'rationale', 'Removing support for unneeded filesystem types reduces the
        local attack surface of the server.'
  desc 'check', 'Run the following commands and verify the output:
        modprobe -n -v freevxfs | grep -E "(freevxfs|install)"
        lsmod | grep freevxfs'
  desc 'fix', 'Edit or create a file in the /etc/modprobe.d/ directory ending
        in .conf and add the following line:
        install freevxfs /bin/true
        Run the following command to unload the freevxfs module:
        rmmod freevxfs'

  tag cis: 'cis-1.1.1.2'
  tag level: 1

  describe kernel_module('freevxfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-1.1.1.3' do
  impact 1.0
  title 'Ensure jffs2 is disabled'
  desc 'The jffs2 (journaling flash filesystem 2) filesystem type is a
        log-structured filesystem used in flash memory devices.'
  desc 'rationale', 'Removing support for unneeded filesystem types reduces the
        local attack surface of the server.'
  desc 'check', 'Run the following commands and verify the output:
        modprobe -n -v jffs2 | grep -E "(jffs2|install)"
        lsmod | grep jffs2'
  desc 'fix', 'Edit or create a file in the /etc/modprobe.d/ directory ending
        in .conf and add the following line:
        install jffs2 /bin/true
        Run the following command to unload the jffs2 module:
        rmmod jffs2'

  tag cis: 'cis-1.1.1.3'
  tag level: 1

  describe kernel_module('jffs2') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-1.1.1.4' do
  impact 1.0
  title 'Ensure hfs is disabled'
  desc 'The hfs filesystem type is a hierarchical filesystem that allows you to
        mount Mac OS filesystems.'
  desc 'rationale', 'Removing support for unneeded filesystem types reduces the
        local attack surface of the server.'
  desc 'check', 'Run the following commands and verify the output:
        modprobe -n -v hfs | grep -E "(hfs|install)"
        lsmod | grep hfs'
  desc 'fix', 'Edit or create a file in the /etc/modprobe.d/ directory ending
        in .conf and add the following line:
        install hfs /bin/true
        Run the following command to unload the hfs module:
        rmmod hfs'

  tag cis: 'cis-1.1.1.4'
  tag level: 1

  describe kernel_module('hfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-1.1.1.5' do
  impact 1.0
  title 'Ensure hfsplus is disabled'
  desc 'The hfsplus filesystem type is a hierarchical filesystem designed to
        replace hfs that allows you to mount Mac OS filesystems.'
  desc 'rationale', 'Removing support for unneeded filesystem types reduces the
        local attack surface of the server.'
  desc 'check', 'Run the following commands and verify the output:
        modprobe -n -v hfsplus | grep -E "(hfsplus|install)"
        lsmod | grep hfsplus'
  desc 'fix', 'Edit or create a file in the /etc/modprobe.d/ directory ending
        in .conf and add the following line:
        install hfsplus /bin/true
        Run the following command to unload the hfsplus module:
        rmmod hfsplus'

  tag cis: 'cis-1.1.1.5'
  tag level: 1

  describe kernel_module('hfsplus') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-1.1.1.6' do
  impact 1.0
  title 'Ensure squashfs is disabled'
  desc 'The squashfs filesystem type is a compressed read-only Linux
        filesystem embedded in small footprint systems. A squashfs image can
        be used without having to first decompress the image.'
  desc 'rationale', 'Removing support for unneeded filesystem types reduces the
        local attack surface of the server.'
  desc 'check', 'Run the following commands and verify the output:
        modprobe -n -v squashfs | grep -E "(squashfs|install)"
        lsmod | grep squashfs'
  desc 'fix', 'Edit or create a file in the /etc/modprobe.d/ directory ending
        in .conf and add the following line:
        install squashfs /bin/true
        Run the following command to unload the squashfs module:
        rmmod squashfs'

  tag cis: 'cis-1.1.1.6'
  tag level: 1

  describe kernel_module('squashfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-1.1.1.7' do
  impact 1.0
  title 'Ensure udf is disabled'
  desc 'The udf filesystem type is the universal disk format used to implement
        ISO/IEC 13346 and ECMA-167 specifications. This is an open vendor
        filesystem type for data storage on a broad range of media. This
        filesystem type is necessary to support writing DVDs and newer optical
        disc formats.'
  desc 'rationale', 'Removing support for unneeded filesystem types reduces the
        local attack surface of the server.'
  desc 'check', 'Run the following commands and verify the output:
        modprobe -n -v udf | grep -E "(udf|install)"
        lsmod | grep udf'
  desc 'fix', 'Edit or create a file in the /etc/modprobe.d/ directory ending
        in .conf and add the following line:
        install udf /bin/true
        Run the following command to unload the udf module:
        rmmod udf'

  tag cis: 'cis-1.1.1.7'
  tag level: 1

  describe kernel_module('udf') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

# -----------------------------------------------------------------------------
# 1.1.2-1.1.5 - /tmp Partition Configuration
# -----------------------------------------------------------------------------

control 'cis-1.1.2' do
  impact 1.0
  title 'Ensure /tmp is configured'
  desc 'The /tmp directory is a world-writable directory used for temporary
        storage by all users and some applications.'
  desc 'rationale', 'Making /tmp its own file system allows an administrator to
        set the noexec option on the mount, making /tmp useless for an attacker
        to install executable code. It would also prevent an attacker from
        establishing a hardlink to a system setuid program and wait for it to
        be updated. Once the program was updated, the hardlink would be
        pointing to the old version of the program while the actual binary
        would be the new version.'
  desc 'check', 'Run the following command and verify that /tmp is mounted:
        mount | grep -E "\s/tmp\s"
        Verify that systemd will mount /tmp at boot:
        systemctl is-enabled tmp.mount'
  desc 'fix', 'Configure /etc/fstab or create a systemd tmp.mount unit file
        to configure /tmp as a separate mount point.'

  tag cis: 'cis-1.1.2'
  tag level: 1

  describe mount('/tmp') do
    it { should be_mounted }
  end
end

control 'cis-1.1.3' do
  impact 1.0
  title 'Ensure nodev option set on /tmp partition'
  desc 'The nodev mount option specifies that the filesystem cannot contain
        special devices.'
  desc 'rationale', 'Since the /tmp filesystem is not intended to support
        devices, set this option to ensure that users cannot attempt to create
        block or character special devices in /tmp.'
  desc 'check', 'Run the following command and verify that nodev is set on
        /tmp: mount | grep -E "\s/tmp\s" | grep -v nodev'
  desc 'fix', 'Edit the /etc/fstab file and add nodev to the fourth field
        (mounting options) for the /tmp partition.'

  tag cis: 'cis-1.1.3'
  tag level: 1

  describe mount('/tmp') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
  end
end

control 'cis-1.1.4' do
  impact 1.0
  title 'Ensure nosuid option set on /tmp partition'
  desc 'The nosuid mount option specifies that the filesystem cannot contain
        setuid files.'
  desc 'rationale', 'Since the /tmp filesystem is only intended for temporary
        file storage, set this option to ensure that users cannot create setuid
        files in /tmp.'
  desc 'check', 'Run the following command and verify that nosuid is set on
        /tmp: mount | grep -E "\s/tmp\s" | grep -v nosuid'
  desc 'fix', 'Edit the /etc/fstab file and add nosuid to the fourth field
        (mounting options) for the /tmp partition.'

  tag cis: 'cis-1.1.4'
  tag level: 1

  describe mount('/tmp') do
    it { should be_mounted }
    its('options') { should include 'nosuid' }
  end
end

control 'cis-1.1.5' do
  impact 1.0
  title 'Ensure noexec option set on /tmp partition'
  desc 'The noexec mount option specifies that the filesystem cannot contain
        executable binaries.'
  desc 'rationale', 'Since the /tmp filesystem is only intended for temporary
        file storage, set this option to ensure that users cannot run
        executable binaries from /tmp.'
  desc 'check', 'Run the following command and verify that noexec is set on
        /tmp: mount | grep -E "\s/tmp\s" | grep -v noexec'
  desc 'fix', 'Edit the /etc/fstab file and add noexec to the fourth field
        (mounting options) for the /tmp partition.'

  tag cis: 'cis-1.1.5'
  tag level: 1

  describe mount('/tmp') do
    it { should be_mounted }
    its('options') { should include 'noexec' }
  end
end

# -----------------------------------------------------------------------------
# 1.1.6-1.1.9 - /var/tmp Partition Configuration
# -----------------------------------------------------------------------------

control 'cis-1.1.6' do
  impact 1.0
  title 'Ensure /var/tmp is configured'
  desc 'The /var/tmp directory is a world-writable directory used for temporary
        storage by all users and some applications.'
  desc 'rationale', 'Since the /var/tmp directory is intended to be
        world-writable, there is a risk of resource exhaustion if it is not
        bound to a separate partition. In addition, making /var/tmp its own
        file system allows an administrator to set the noexec option on the
        mount, making /var/tmp useless for an attacker to install executable
        code.'
  desc 'check', 'Run the following command and verify that /var/tmp is mounted:
        mount | grep -E "\s/var/tmp\s"'
  desc 'fix', 'For new installations, during installation create a custom
        partition setup and specify a separate partition for /var/tmp.
        For systems that were previously installed, create a new partition and
        configure /etc/fstab as appropriate.'

  tag cis: 'cis-1.1.6'
  tag level: 1

  describe mount('/var/tmp') do
    it { should be_mounted }
  end
end

control 'cis-1.1.7' do
  impact 1.0
  title 'Ensure nodev option set on /var/tmp partition'
  desc 'The nodev mount option specifies that the filesystem cannot contain
        special devices.'
  desc 'rationale', 'Since the /var/tmp filesystem is not intended to support
        devices, set this option to ensure that users cannot attempt to create
        block or character special devices in /var/tmp.'
  desc 'check', 'Run the following command and verify that nodev is set on
        /var/tmp: mount | grep -E "\s/var/tmp\s" | grep -v nodev'
  desc 'fix', 'Edit the /etc/fstab file and add nodev to the fourth field
        (mounting options) for the /var/tmp partition.'

  tag cis: 'cis-1.1.7'
  tag level: 1

  describe mount('/var/tmp') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
  end
end

control 'cis-1.1.8' do
  impact 1.0
  title 'Ensure nosuid option set on /var/tmp partition'
  desc 'The nosuid mount option specifies that the filesystem cannot contain
        setuid files.'
  desc 'rationale', 'Since the /var/tmp filesystem is only intended for
        temporary file storage, set this option to ensure that users cannot
        create setuid files in /var/tmp.'
  desc 'check', 'Run the following command and verify that nosuid is set on
        /var/tmp: mount | grep -E "\s/var/tmp\s" | grep -v nosuid'
  desc 'fix', 'Edit the /etc/fstab file and add nosuid to the fourth field
        (mounting options) for the /var/tmp partition.'

  tag cis: 'cis-1.1.8'
  tag level: 1

  describe mount('/var/tmp') do
    it { should be_mounted }
    its('options') { should include 'nosuid' }
  end
end

control 'cis-1.1.9' do
  impact 1.0
  title 'Ensure noexec option set on /var/tmp partition'
  desc 'The noexec mount option specifies that the filesystem cannot contain
        executable binaries.'
  desc 'rationale', 'Since the /var/tmp filesystem is only intended for
        temporary file storage, set this option to ensure that users cannot
        run executable binaries from /var/tmp.'
  desc 'check', 'Run the following command and verify that noexec is set on
        /var/tmp: mount | grep -E "\s/var/tmp\s" | grep -v noexec'
  desc 'fix', 'Edit the /etc/fstab file and add noexec to the fourth field
        (mounting options) for the /var/tmp partition.'

  tag cis: 'cis-1.1.9'
  tag level: 1

  describe mount('/var/tmp') do
    it { should be_mounted }
    its('options') { should include 'noexec' }
  end
end

# -----------------------------------------------------------------------------
# 1.1.14 - /home Partition Configuration
# -----------------------------------------------------------------------------

control 'cis-1.1.14' do
  impact 1.0
  title 'Ensure nodev option set on /home partition'
  desc 'The nodev mount option specifies that the filesystem cannot contain
        special devices.'
  desc 'rationale', 'Since the user partitions are not intended to support
        devices, set this option to ensure that users cannot attempt to create
        block or character special devices.'
  desc 'check', 'Run the following command and verify that nodev is set on
        /home: mount | grep -E "\s/home\s" | grep -v nodev'
  desc 'fix', 'Edit the /etc/fstab file and add nodev to the fourth field
        (mounting options) for the /home partition.'

  tag cis: 'cis-1.1.14'
  tag level: 1

  only_if('This control is only applicable if /home is a separate partition') do
    mount('/home').mounted?
  end

  describe mount('/home') do
    its('options') { should include 'nodev' }
  end
end

# -----------------------------------------------------------------------------
# 1.1.15-1.1.17 - /dev/shm Partition Configuration
# -----------------------------------------------------------------------------

control 'cis-1.1.15' do
  impact 1.0
  title 'Ensure nodev option set on /dev/shm partition'
  desc 'The nodev mount option specifies that the filesystem cannot contain
        special devices.'
  desc 'rationale', 'Since the /dev/shm filesystem is not intended to support
        devices, set this option to ensure that users cannot attempt to create
        block or character special devices in /dev/shm partitions.'
  desc 'check', 'Run the following command and verify that nodev is set on
        /dev/shm: mount | grep -E "\s/dev/shm\s" | grep -v nodev'
  desc 'fix', 'Edit the /etc/fstab file and add nodev to the fourth field
        (mounting options) for the /dev/shm partition.'

  tag cis: 'cis-1.1.15'
  tag level: 1

  describe mount('/dev/shm') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
  end
end

control 'cis-1.1.16' do
  impact 1.0
  title 'Ensure nosuid option set on /dev/shm partition'
  desc 'The nosuid mount option specifies that the filesystem cannot contain
        setuid files.'
  desc 'rationale', 'Setting this option on a file system prevents users from
        introducing privileged programs onto the system and allowing
        non-root users to execute them.'
  desc 'check', 'Run the following command and verify that nosuid is set on
        /dev/shm: mount | grep -E "\s/dev/shm\s" | grep -v nosuid'
  desc 'fix', 'Edit the /etc/fstab file and add nosuid to the fourth field
        (mounting options) for the /dev/shm partition.'

  tag cis: 'cis-1.1.16'
  tag level: 1

  describe mount('/dev/shm') do
    it { should be_mounted }
    its('options') { should include 'nosuid' }
  end
end

control 'cis-1.1.17' do
  impact 1.0
  title 'Ensure noexec option set on /dev/shm partition'
  desc 'The noexec mount option specifies that the filesystem cannot contain
        executable binaries.'
  desc 'rationale', 'Setting this option on a file system prevents users from
        executing programs from shared memory. This deters users from
        introducing potentially malicious software on the system.'
  desc 'check', 'Run the following command and verify that noexec is set on
        /dev/shm: mount | grep -E "\s/dev/shm\s" | grep -v noexec'
  desc 'fix', 'Edit the /etc/fstab file and add noexec to the fourth field
        (mounting options) for the /dev/shm partition.'

  tag cis: 'cis-1.1.17'
  tag level: 1

  describe mount('/dev/shm') do
    it { should be_mounted }
    its('options') { should include 'noexec' }
  end
end

# -----------------------------------------------------------------------------
# 1.1.21-1.1.23 - Additional Filesystem Configuration
# -----------------------------------------------------------------------------

control 'cis-1.1.21' do
  impact 1.0
  title 'Ensure sticky bit is set on all world-writable directories'
  desc 'Setting the sticky bit on world writable directories prevents users
        from deleting or renaming files in that directory that are not owned
        by them.'
  desc 'rationale', 'This feature prevents the ability to delete or rename
        files in world writable directories (such as /tmp) that are owned by
        another user.'
  desc 'check', 'Run the following command and verify no output is returned:
        df --local -P | awk "{if (NR!=1) print \$6}" | xargs -I "{}" find "{}"
        -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null'
  desc 'fix', 'Run the following command to set the sticky bit on all world
        writable directories:
        df --local -P | awk "{if (NR!=1) print \$6}" | xargs -I "{}" find "{}"
        -xdev -type d -perm -0002 2>/dev/null | xargs -I "{}" chmod a+t "{}"'

  tag cis: 'cis-1.1.21'
  tag level: 1

  describe command('df --local -P 2>/dev/null | awk \'{if (NR!=1) print $6}\' | xargs -I \'{}\' find \'{}\' -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) 2>/dev/null') do
    its('stdout') { should eq '' }
  end
end

control 'cis-1.1.22' do
  impact 1.0
  title 'Disable Automounting'
  desc 'autofs allows automatic mounting of devices, typically including CD/DVDs
        and USB drives.'
  desc 'rationale', 'With automounting enabled anyone with physical access could
        attach a USB drive or disc and have its contents available in system
        even if they lacked permissions to mount it themselves.'
  desc 'check', 'Run the following command to verify autofs is not enabled:
        systemctl is-enabled autofs'
  desc 'fix', 'Run the following command to disable autofs:
        systemctl --now disable autofs'

  tag cis: 'cis-1.1.22'
  tag level: 1

  describe.one do
    describe service('autofs') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
    describe package('autofs') do
      it { should_not be_installed }
    end
  end
end

control 'cis-1.1.23' do
  impact 1.0
  title 'Disable USB Storage'
  desc 'USB storage provides a means to transfer and store files insuring
        persistence and availability of the files independent of network
        connection status. Its popularity and utility has led to USB-based
        malware being a simple and common means for network infiltration and
        a first step to establishing a persistent threat within a networked
        environment.'
  desc 'rationale', 'Restricting USB access on the system will decrease the
        physical attack surface for a device and diminish the possible vectors
        to introduce malware.'
  desc 'check', 'Run the following commands and verify the output:
        modprobe -n -v usb-storage
        lsmod | grep usb-storage'
  desc 'fix', 'Edit or create a file in the /etc/modprobe.d/ directory ending
        in .conf and add the following line:
        install usb-storage /bin/true
        Run the following command to unload the usb-storage module:
        rmmod usb-storage'

  tag cis: 'cis-1.1.23'
  tag level: 1

  describe kernel_module('usb-storage') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end
