# frozen_string_literal: true

#
# CIS Benchmark Controls - Section 4.1: Configure System Accounting (auditd)
#

control 'cis-4.1.1.1' do
  impact 1.0
  title 'Ensure auditd is installed'
  desc 'auditd is the userspace component to the Linux Auditing System. It is responsible for writing audit records to the disk.'
  desc 'rationale', 'The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring.'
  desc 'check', 'Run the following command and verify auditd is installed: dpkg -s auditd audispd-plugins'
  desc 'fix', 'Run the following command to install auditd: apt install auditd audispd-plugins'

  tag cis: '4.1.1.1'
  tag level: 2

  if os.debian?
    describe package('auditd') do
      it { should be_installed }
    end

    describe package('audispd-plugins') do
      it { should be_installed }
    end
  elsif os.redhat?
    describe package('audit') do
      it { should be_installed }
    end

    describe package('audit-libs') do
      it { should be_installed }
    end
  end
end

control 'cis-4.1.1.2' do
  impact 1.0
  title 'Ensure auditd service is enabled and running'
  desc 'Turn on the auditd daemon to record system events.'
  desc 'rationale', 'The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring.'
  desc 'check', 'Run the following command to verify auditd is enabled: systemctl is-enabled auditd'
  desc 'fix', 'Run the following command to enable auditd: systemctl --now enable auditd'

  tag cis: '4.1.1.2'
  tag level: 2

  describe service('auditd') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

control 'cis-4.1.1.3' do
  impact 1.0
  title 'Ensure auditing for processes that start prior to auditd is enabled'
  desc 'Configure grub so that processes that are capable of being audited can be audited even if they start up prior to auditd startup.'
  desc 'rationale', 'Audit events need to be captured on processes that start up prior to auditd, so that potential malicious activity cannot go undetected.'
  desc 'check', 'Run the following command and verify audit=1 is set: grep "^\s*linux" /boot/grub/grub.cfg | grep -v "audit=1"'
  desc 'fix', 'Edit /etc/default/grub and add audit=1 to GRUB_CMDLINE_LINUX, then run update-grub'

  tag cis: '4.1.1.3'
  tag level: 2

  grub_conf = command('grep "^\s*linux" /boot/grub/grub.cfg 2>/dev/null || grep "^\s*linux" /boot/grub2/grub.cfg 2>/dev/null').stdout

  describe grub_conf do
    it { should match(/audit=1/) }
  end

  # Also check /etc/default/grub for persistence
  describe file('/etc/default/grub') do
    its('content') { should match(/GRUB_CMDLINE_LINUX.*audit=1/) }
  end
end

control 'cis-4.1.2.1' do
  impact 1.0
  title 'Ensure audit log storage size is configured'
  desc 'Configure the maximum size of the audit log file. Once the log reaches the maximum size, it will be rotated and a new log file will be started.'
  desc 'rationale', 'It is important that an appropriate size is determined for log files so that they do not impact the system and audit data is not lost.'
  desc 'check', 'Run the following command and ensure output is in compliance with site policy: grep max_log_file /etc/audit/auditd.conf'
  desc 'fix', 'Set the following parameter in /etc/audit/auditd.conf in accordance with site policy: max_log_file = <MB>'

  tag cis: '4.1.2.1'
  tag level: 2

  describe auditd_conf do
    its('max_log_file') { should_not be_nil }
    its('max_log_file') { should cmp >= 8 }
  end
end

control 'cis-4.1.2.2' do
  impact 1.0
  title 'Ensure audit logs are not automatically deleted'
  desc 'The max_log_file_action setting determines how to handle the audit log file reaching the max file size.'
  desc 'rationale', 'In high security contexts, the benefits of maintaining a long audit history exceed the cost of storing the audit history.'
  desc 'check', 'Run the following command and verify output matches: grep max_log_file_action /etc/audit/auditd.conf'
  desc 'fix', 'Set the following parameter in /etc/audit/auditd.conf: max_log_file_action = keep_logs'

  tag cis: '4.1.2.2'
  tag level: 2

  describe auditd_conf do
    its('max_log_file_action') { should cmp 'keep_logs' }
  end
end

control 'cis-4.1.2.3' do
  impact 1.0
  title 'Ensure system is disabled when audit logs are full'
  desc 'The auditd daemon can be configured to halt the system when the audit logs are full.'
  desc 'rationale', 'In high security contexts, the risk of detecting unauthorized access or nonrepudiation exceeds the benefit of the systems availability.'
  desc 'check', 'Run the following commands and verify output: grep space_left_action /etc/audit/auditd.conf; grep action_mail_acct /etc/audit/auditd.conf; grep admin_space_left_action /etc/audit/auditd.conf'
  desc 'fix', 'Set the following parameters in /etc/audit/auditd.conf: space_left_action = email, action_mail_acct = root, admin_space_left_action = halt'

  tag cis: '4.1.2.3'
  tag level: 2

  describe auditd_conf do
    its('space_left_action') { should cmp 'email' }
    its('action_mail_acct') { should cmp 'root' }
    its('admin_space_left_action') { should cmp 'halt' }
  end
end

control 'cis-4.1.3' do
  impact 1.0
  title 'Ensure events that modify date and time information are collected'
  desc 'Capture events where the system date and/or time has been modified.'
  desc 'rationale', 'Unexpected changes in system date and/or time could be a sign of malicious activity on the system.'
  desc 'check', 'Run the following commands and verify the output matches the expected audit rules for time-change'
  desc 'fix', 'Add the appropriate rules to /etc/audit/rules.d/time-change.rules'

  tag cis: '4.1.3'
  tag level: 2

  audit_rules_content = command('auditctl -l').stdout

  # Check for adjtimex syscall
  describe audit_rules_content do
    it { should match(/-a always,exit -F arch=b64 -S adjtimex.*-k time-change/) }
    it { should match(/-a always,exit -F arch=b32 -S adjtimex.*-k time-change/) }
  end

  # Check for settimeofday syscall
  describe audit_rules_content do
    it { should match(/-a always,exit -F arch=b64 -S settimeofday.*-k time-change/) }
    it { should match(/-a always,exit -F arch=b32 -S settimeofday.*-k time-change/) }
  end

  # Check for stime syscall (32-bit only)
  describe audit_rules_content do
    it { should match(/-a always,exit -F arch=b32 -S stime.*-k time-change/) }
  end

  # Check for clock_settime syscall
  describe audit_rules_content do
    it { should match(/-a always,exit -F arch=b64 -S clock_settime.*-k time-change/) }
    it { should match(/-a always,exit -F arch=b32 -S clock_settime.*-k time-change/) }
  end

  # Check for /etc/localtime watch
  describe audit_rules_content do
    it { should match(/-w \/etc\/localtime -p wa -k time-change/) }
  end
end

control 'cis-4.1.4' do
  impact 1.0
  title 'Ensure events that modify user/group information are collected'
  desc 'Record events affecting the group, passwd (user IDs), shadow and gshadow (passwords) or /etc/security/opasswd (old passwords, based on remember parameter in the PAM configuration) files.'
  desc 'rationale', 'Unexpected changes to these files could be an indication that the system has been compromised and that an unauthorized user is attempting to hide their activities or compromise additional accounts.'
  desc 'check', 'Run the following command and verify the audit rules for identity modification'
  desc 'fix', 'Add the appropriate rules to /etc/audit/rules.d/identity.rules'

  tag cis: '4.1.4'
  tag level: 2

  audit_rules_content = command('auditctl -l').stdout

  describe audit_rules_content do
    it { should match(/-w \/etc\/group -p wa -k identity/) }
    it { should match(/-w \/etc\/passwd -p wa -k identity/) }
    it { should match(/-w \/etc\/gshadow -p wa -k identity/) }
    it { should match(/-w \/etc\/shadow -p wa -k identity/) }
    it { should match(/-w \/etc\/security\/opasswd -p wa -k identity/) }
  end
end

control 'cis-4.1.5' do
  impact 1.0
  title 'Ensure events that modify the system\'s network environment are collected'
  desc 'Record changes to network environment files or system calls.'
  desc 'rationale', 'Monitoring sethostname and setdomainname will identify potential unauthorized changes to host and domainname. Monitoring /etc/issue and /etc/issue.net will identify potential unauthorized changes to login banners.'
  desc 'check', 'Run the following command and verify the audit rules for system-locale'
  desc 'fix', 'Add the appropriate rules to /etc/audit/rules.d/system-locale.rules'

  tag cis: '4.1.5'
  tag level: 2

  audit_rules_content = command('auditctl -l').stdout

  describe audit_rules_content do
    it { should match(/-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale/) }
    it { should match(/-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale/) }
    it { should match(/-w \/etc\/issue -p wa -k system-locale/) }
    it { should match(/-w \/etc\/issue\.net -p wa -k system-locale/) }
    it { should match(/-w \/etc\/hosts -p wa -k system-locale/) }
    it { should match(/-w \/etc\/network -p wa -k system-locale/) }
  end
end

control 'cis-4.1.6' do
  impact 1.0
  title 'Ensure events that modify the system\'s Mandatory Access Controls are collected'
  desc 'Monitor SELinux/AppArmor mandatory access controls.'
  desc 'rationale', 'Changes to MAC policy could indicate that an unauthorized user is attempting to modify security controls that were put in place to contain malicious activity.'
  desc 'check', 'Run the following command and verify the audit rules for MAC-policy'
  desc 'fix', 'Add the appropriate rules to /etc/audit/rules.d/MAC-policy.rules'

  tag cis: '4.1.6'
  tag level: 2

  audit_rules_content = command('auditctl -l').stdout

  # Check for SELinux or AppArmor monitoring depending on system
  if file('/etc/selinux').exist?
    describe audit_rules_content do
      it { should match(/-w \/etc\/selinux\/ -p wa -k MAC-policy/) }
      it { should match(/-w \/usr\/share\/selinux\/ -p wa -k MAC-policy/) }
    end
  end

  if file('/etc/apparmor').exist? || file('/etc/apparmor.d').exist?
    describe audit_rules_content do
      it { should match(/-w \/etc\/apparmor\/ -p wa -k MAC-policy/) }
      it { should match(/-w \/etc\/apparmor\.d\/ -p wa -k MAC-policy/) }
    end
  end
end

control 'cis-4.1.7' do
  impact 1.0
  title 'Ensure login and logout events are collected'
  desc 'Monitor login and logout events.'
  desc 'rationale', 'Monitoring login/logout events could provide a system administrator with information associated with brute force attacks against user logins.'
  desc 'check', 'Run the following command and verify the audit rules for logins'
  desc 'fix', 'Add the appropriate rules to /etc/audit/rules.d/logins.rules'

  tag cis: '4.1.7'
  tag level: 2

  audit_rules_content = command('auditctl -l').stdout

  describe audit_rules_content do
    it { should match(/-w \/var\/log\/faillog -p wa -k logins/) }
    it { should match(/-w \/var\/log\/lastlog -p wa -k logins/) }
    it { should match(/-w \/var\/log\/tallylog -p wa -k logins/) }
  end
end

control 'cis-4.1.8' do
  impact 1.0
  title 'Ensure session initiation information is collected'
  desc 'Monitor session initiation events.'
  desc 'rationale', 'Monitoring these files for changes could alert a system administrator to logins occurring at unusual hours, which could indicate intruder activity.'
  desc 'check', 'Run the following command and verify the audit rules for session'
  desc 'fix', 'Add the appropriate rules to /etc/audit/rules.d/session.rules'

  tag cis: '4.1.8'
  tag level: 2

  audit_rules_content = command('auditctl -l').stdout

  describe audit_rules_content do
    it { should match(/-w \/var\/run\/utmp -p wa -k session/) }
    it { should match(/-w \/var\/log\/wtmp -p wa -k session/) }
    it { should match(/-w \/var\/log\/btmp -p wa -k session/) }
  end
end

control 'cis-4.1.9' do
  impact 1.0
  title 'Ensure discretionary access control permission modification events are collected'
  desc 'Monitor changes to file permissions, attributes, ownership and group.'
  desc 'rationale', 'Monitoring for changes in file attributes could alert a system administrator to activity that could indicate intruder activity or policy violation.'
  desc 'check', 'Run the following command and verify the audit rules for perm_mod'
  desc 'fix', 'Add the appropriate rules to /etc/audit/rules.d/perm_mod.rules'

  tag cis: '4.1.9'
  tag level: 2

  audit_rules_content = command('auditctl -l').stdout

  describe audit_rules_content do
    it { should match(/-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod/) }
    it { should match(/-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod/) }
    it { should match(/-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod/) }
    it { should match(/-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod/) }
    it { should match(/-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod/) }
    it { should match(/-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod/) }
  end
end

control 'cis-4.1.10' do
  impact 1.0
  title 'Ensure unsuccessful unauthorized file access attempts are collected'
  desc 'Monitor for unsuccessful attempts to access files.'
  desc 'rationale', 'Failed attempts to open, create or truncate files could be an indication that an individual or process is trying to gain unauthorized access to the system.'
  desc 'check', 'Run the following command and verify the audit rules for access'
  desc 'fix', 'Add the appropriate rules to /etc/audit/rules.d/access.rules'

  tag cis: '4.1.10'
  tag level: 2

  audit_rules_content = command('auditctl -l').stdout

  describe audit_rules_content do
    it { should match(/-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access/) }
    it { should match(/-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access/) }
    it { should match(/-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access/) }
    it { should match(/-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access/) }
  end
end

control 'cis-4.1.11' do
  impact 1.0
  title 'Ensure use of privileged commands is collected'
  desc 'Monitor privileged programs (those that have the setuid and/or setgid bit set on execution) to determine if unprivileged users are running these commands.'
  desc 'rationale', 'Execution of privileged commands by non-privileged users could be an indication of someone trying to gain unauthorized access to the system.'
  desc 'check', 'Run the following command to find all privileged commands and verify audit rules exist for each'
  desc 'fix', 'Add audit rules for all privileged commands found on the system'

  tag cis: '4.1.11'
  tag level: 2

  audit_rules_content = command('auditctl -l').stdout

  # Get list of privileged commands
  privileged_commands = command('find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null').stdout.split("\n")

  privileged_commands.each do |cmd|
    next if cmd.empty?

    describe audit_rules_content do
      it { should match(/-a always,exit -F path=#{Regexp.escape(cmd)} -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged/) }
    end
  end
end

control 'cis-4.1.12' do
  impact 1.0
  title 'Ensure successful file system mounts are collected'
  desc 'Monitor the use of the mount system call.'
  desc 'rationale', 'It is highly unusual for a non privileged user to mount file systems to the system. While tracking mount commands gives the system administrator evidence that external media may have been mounted, it does not indicate what is on that media.'
  desc 'check', 'Run the following command and verify the audit rules for mounts'
  desc 'fix', 'Add the appropriate rules to /etc/audit/rules.d/mounts.rules'

  tag cis: '4.1.12'
  tag level: 2

  audit_rules_content = command('auditctl -l').stdout

  describe audit_rules_content do
    it { should match(/-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts/) }
    it { should match(/-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts/) }
  end
end

control 'cis-4.1.13' do
  impact 1.0
  title 'Ensure file deletion events by users are collected'
  desc 'Monitor the use of system calls associated with the deletion or renaming of files and file attributes.'
  desc 'rationale', 'Monitoring these calls from non-privileged users could provide a system administrator with evidence that inappropriate removal of files and file attributes associated with protected files is occurring.'
  desc 'check', 'Run the following command and verify the audit rules for delete'
  desc 'fix', 'Add the appropriate rules to /etc/audit/rules.d/delete.rules'

  tag cis: '4.1.13'
  tag level: 2

  audit_rules_content = command('auditctl -l').stdout

  describe audit_rules_content do
    it { should match(/-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete/) }
    it { should match(/-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete/) }
  end
end

control 'cis-4.1.14' do
  impact 1.0
  title 'Ensure changes to system administration scope (sudoers) is collected'
  desc 'Monitor scope changes for system administrators.'
  desc 'rationale', 'Changes in the /etc/sudoers file can indicate that an unauthorized change has been made to the scope of system administrator activity.'
  desc 'check', 'Run the following command and verify the audit rules for scope'
  desc 'fix', 'Add the appropriate rules to /etc/audit/rules.d/scope.rules'

  tag cis: '4.1.14'
  tag level: 2

  audit_rules_content = command('auditctl -l').stdout

  describe audit_rules_content do
    it { should match(/-w \/etc\/sudoers -p wa -k scope/) }
    it { should match(/-w \/etc\/sudoers\.d\/ -p wa -k scope/) }
  end
end

control 'cis-4.1.15' do
  impact 1.0
  title 'Ensure system administrator command executions (sudo) are collected'
  desc 'Monitor the sudo log file.'
  desc 'rationale', 'Changes in /var/log/sudo.log indicate that an administrator has executed a command or the log file itself has been tampered with.'
  desc 'check', 'Run the following command and verify the audit rules for actions'
  desc 'fix', 'Add the appropriate rules to /etc/audit/rules.d/actions.rules'

  tag cis: '4.1.15'
  tag level: 2

  audit_rules_content = command('auditctl -l').stdout

  # Check for execve monitoring for sudo/su
  describe audit_rules_content do
    it { should match(/-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -S execve -k actions/) }
    it { should match(/-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -S execve -k actions/) }
  end
end

control 'cis-4.1.16' do
  impact 1.0
  title 'Ensure kernel module loading and unloading is collected'
  desc 'Monitor the loading and unloading of kernel modules.'
  desc 'rationale', 'Monitoring the use of insmod, rmmod and modprobe could provide system administrators with evidence that an unauthorized user loaded or unloaded a kernel module, possibly compromising the security of the system.'
  desc 'check', 'Run the following command and verify the audit rules for modules'
  desc 'fix', 'Add the appropriate rules to /etc/audit/rules.d/modules.rules'

  tag cis: '4.1.16'
  tag level: 2

  audit_rules_content = command('auditctl -l').stdout

  describe audit_rules_content do
    it { should match(/-w \/sbin\/insmod -p x -k modules/) }
    it { should match(/-w \/sbin\/rmmod -p x -k modules/) }
    it { should match(/-w \/sbin\/modprobe -p x -k modules/) }
    it { should match(/-a always,exit -F arch=b64 -S init_module -S delete_module -k modules/) }
  end
end

control 'cis-4.1.17' do
  impact 1.0
  title 'Ensure the audit configuration is immutable'
  desc 'Set system audit so that audit rules cannot be modified using auditctl.'
  desc 'rationale', 'In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back.'
  desc 'check', 'Run the following command and verify output includes "-e 2": grep "^\s*[^#]" /etc/audit/rules.d/*.rules | tail -1'
  desc 'fix', 'Add the following line to the end of /etc/audit/rules.d/99-finalize.rules: -e 2'

  tag cis: '4.1.17'
  tag level: 2

  # Check that -e 2 is set (makes audit rules immutable)
  # This should be the last rule in the audit configuration
  describe command('grep -h "^\s*-e\s*2" /etc/audit/rules.d/*.rules') do
    its('stdout') { should match(/-e 2/) }
  end

  # Verify the immutable flag is in a finalize rules file to ensure it's loaded last
  describe file('/etc/audit/rules.d/99-finalize.rules') do
    it { should exist }
    its('content') { should match(/^\s*-e\s+2/) }
  end
end
