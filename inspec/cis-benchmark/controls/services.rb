# CIS Benchmark Controls - Services and File Permissions
# Section 2.2: Disabled Services
# Section 2.3: Required Services
# Section 6.1: File Permissions

# =============================================================================
# Section 2.2 - Disabled Services
# =============================================================================

control 'cis-2.2.1' do
  impact 1.0
  title 'Ensure xinetd is not installed'
  desc 'The eXtended InterNET Daemon (xinetd) is an open source super daemon that replaced the original inetd daemon. The xinetd daemon listens for well known services and dispatches the appropriate daemon to properly respond to service requests.'
  desc 'rationale', 'If there are no xinetd services required, it is recommended that the package be removed to reduce the attack surface area.'

  tag cis: '2.2.1'
  tag level: 1

  describe package('xinetd') do
    it { should_not be_installed }
  end
end

control 'cis-2.2.2' do
  impact 1.0
  title 'Ensure xorg-x11-server is not installed'
  desc 'The X Window System provides a Graphical User Interface (GUI) where users can have multiple windows in which to run programs and various add on utilities.'
  desc 'rationale', 'Unless your organization specifically requires graphical login access via X Windows, remove it to reduce the potential attack surface.'

  tag cis: '2.2.2'
  tag level: 1

  describe package('xorg-x11-server-Xorg') do
    it { should_not be_installed }
  end

  describe package('xorg-x11-server-common') do
    it { should_not be_installed }
  end

  describe package('xserver-xorg') do
    it { should_not be_installed }
  end
end

control 'cis-2.2.3' do
  impact 1.0
  title 'Ensure Avahi Server is not installed or disabled'
  desc 'Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD service discovery. Avahi allows programs to publish and discover services and hosts running on a local network with no specific configuration.'
  desc 'rationale', 'Automatic discovery of network services is not normally required for system functionality. It is recommended to remove this package to reduce the potential attack surface.'

  tag cis: '2.2.3'
  tag level: 1

  describe.one do
    describe package('avahi') do
      it { should_not be_installed }
    end

    describe package('avahi-daemon') do
      it { should_not be_installed }
    end

    describe service('avahi-daemon') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  end
end

control 'cis-2.2.4' do
  impact 1.0
  title 'Ensure CUPS is not installed or disabled'
  desc 'The Common Unix Print System (CUPS) provides the ability to print to both local and network printers. A system running CUPS can also accept print jobs from remote systems and print them to local printers.'
  desc 'rationale', 'If the system does not need to print jobs or accept print jobs from other systems, it is recommended that CUPS be removed or disabled to reduce the potential attack surface.'

  tag cis: '2.2.4'
  tag level: 1

  describe.one do
    describe package('cups') do
      it { should_not be_installed }
    end

    describe service('cups') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  end
end

control 'cis-2.2.5' do
  impact 1.0
  title 'Ensure DHCP Server is not installed'
  desc 'The Dynamic Host Configuration Protocol (DHCP) is a service that allows machines to be dynamically assigned IP addresses.'
  desc 'rationale', 'Unless a system is specifically set up to act as a DHCP server, it is recommended that this package be removed to reduce the potential attack surface.'

  tag cis: '2.2.5'
  tag level: 1

  describe package('dhcp-server') do
    it { should_not be_installed }
  end

  describe package('dhcp') do
    it { should_not be_installed }
  end

  describe package('isc-dhcp-server') do
    it { should_not be_installed }
  end
end

control 'cis-2.2.6' do
  impact 1.0
  title 'Ensure LDAP server is not installed'
  desc 'The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database.'
  desc 'rationale', 'If the system will not need to act as an LDAP server, it is recommended that the software be removed to reduce the potential attack surface.'

  tag cis: '2.2.6'
  tag level: 1

  describe package('openldap-servers') do
    it { should_not be_installed }
  end

  describe package('slapd') do
    it { should_not be_installed }
  end
end

control 'cis-2.2.7' do
  impact 1.0
  title 'Ensure NFS is not installed or disabled'
  desc 'The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX environment. It provides the ability for systems to mount file systems of other servers through the network.'
  desc 'rationale', 'If the system does not export NFS shares or act as an NFS client, it is recommended that these services be removed to reduce the remote attack surface.'

  tag cis: '2.2.7'
  tag level: 1

  describe.one do
    describe package('nfs-utils') do
      it { should_not be_installed }
    end

    describe package('nfs-kernel-server') do
      it { should_not be_installed }
    end

    describe service('nfs-server') do
      it { should_not be_enabled }
      it { should_not be_running }
    end

    describe service('nfs-kernel-server') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  end
end

control 'cis-2.2.8' do
  impact 1.0
  title 'Ensure DNS Server is not installed'
  desc 'The Domain Name System (DNS) is a hierarchical naming system that maps names to IP addresses for computers, services and other resources connected to a network.'
  desc 'rationale', 'Unless a system is specifically designated to act as a DNS server, it is recommended that the package be deleted to reduce the potential attack surface.'

  tag cis: '2.2.8'
  tag level: 1

  describe package('bind') do
    it { should_not be_installed }
  end

  describe package('bind9') do
    it { should_not be_installed }
  end
end

control 'cis-2.2.9' do
  impact 1.0
  title 'Ensure FTP Server is not installed'
  desc 'The File Transfer Protocol (FTP) provides networked computers with the ability to transfer files.'
  desc 'rationale', 'FTP does not protect the confidentiality of data or authentication credentials. It is recommended SFTP be used if file transfer is required. Unless there is a need to run the system as a FTP server, it is recommended that the package be removed to reduce the potential attack surface.'

  tag cis: '2.2.9'
  tag level: 1

  describe package('vsftpd') do
    it { should_not be_installed }
  end

  describe package('proftpd') do
    it { should_not be_installed }
  end

  describe package('pure-ftpd') do
    it { should_not be_installed }
  end
end

control 'cis-2.2.10' do
  impact 1.0
  title 'Ensure HTTP Server is not installed'
  desc 'HTTP or web servers provide the ability to host web site content.'
  desc 'rationale', 'Unless there is a need to run the system as a web server, it is recommended that the packages be removed to reduce the potential attack surface.'

  tag cis: '2.2.10'
  tag level: 1

  describe package('httpd') do
    it { should_not be_installed }
  end

  describe package('apache2') do
    it { should_not be_installed }
  end

  describe package('nginx') do
    it { should_not be_installed }
  end
end

control 'cis-2.2.11' do
  impact 1.0
  title 'Ensure IMAP and POP3 server are not installed'
  desc 'Dovecot is an open source IMAP and POP3 server for Linux based systems.'
  desc 'rationale', 'Unless POP3 and/or IMAP servers are to be provided by this system, it is recommended that the package be removed to reduce the potential attack surface.'

  tag cis: '2.2.11'
  tag level: 1

  describe package('dovecot') do
    it { should_not be_installed }
  end

  describe package('dovecot-core') do
    it { should_not be_installed }
  end

  describe package('dovecot-imapd') do
    it { should_not be_installed }
  end

  describe package('dovecot-pop3d') do
    it { should_not be_installed }
  end

  describe package('cyrus-imapd') do
    it { should_not be_installed }
  end
end

control 'cis-2.2.12' do
  impact 1.0
  title 'Ensure Samba is not installed'
  desc 'The Samba daemon allows system administrators to configure their Linux systems to share file systems and directories with Windows desktops. Samba will advertise the file systems and directories via the Server Message Block (SMB) protocol.'
  desc 'rationale', 'If there is no need to mount directories and file systems to Windows systems, then this service should be removed to reduce the potential attack surface.'

  tag cis: '2.2.12'
  tag level: 1

  describe package('samba') do
    it { should_not be_installed }
  end
end

control 'cis-2.2.13' do
  impact 1.0
  title 'Ensure SNMP Server is not installed'
  desc 'Simple Network Management Protocol (SNMP) is a widely used protocol for monitoring the health and welfare of network equipment, computer equipment and devices like UPSs.'
  desc 'rationale', 'The SNMP server can communicate using SNMPv1, which transmits data in the clear and does not require authentication to execute commands. SNMPv3 replaces the simple/clear text password sharing used in SNMPv2 with more securely encoded parameters. If the SNMP service is not required, the net-snmp package should be removed to reduce the attack surface of the system.'

  tag cis: '2.2.13'
  tag level: 1

  describe package('net-snmp') do
    it { should_not be_installed }
  end

  describe package('snmpd') do
    it { should_not be_installed }
  end
end

control 'cis-2.2.14' do
  impact 1.0
  title 'Ensure telnet-server is not installed'
  desc 'The telnet-server package contains the telnet daemon, which accepts connections from users from other systems via the telnet protocol.'
  desc 'rationale', 'The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow a user with access to sniff network traffic the ability to steal credentials. The ssh package provides an encrypted session and stronger security.'

  tag cis: '2.2.14'
  tag level: 1

  describe package('telnet-server') do
    it { should_not be_installed }
  end

  describe package('telnetd') do
    it { should_not be_installed }
  end
end

control 'cis-2.2.15' do
  impact 1.0
  title 'Ensure rsh server is not installed'
  desc 'The Berkeley rsh-server (rsh, rlogin, rexec) package contains legacy services that exchange credentials in clear-text.'
  desc 'rationale', 'These legacy services contain numerous security exposures and have been replaced with the more secure SSH package. Even if the server is removed, it is best to also ensure the clients are also removed to prevent users from inadvertently attempting to use these commands and therefore exposing their credentials.'

  tag cis: '2.2.15'
  tag level: 1

  describe package('rsh-server') do
    it { should_not be_installed }
  end

  describe package('rsh') do
    it { should_not be_installed }
  end
end

# =============================================================================
# Section 2.3 - Required Services
# =============================================================================

control 'cis-2.3.1' do
  impact 1.0
  title 'Ensure NTP or chrony is installed and configured'
  desc 'System time should be synchronized between all systems in an environment. This is typically done by establishing an authoritative time server or set of servers and having all systems synchronize their clocks to them.'
  desc 'rationale', 'Time synchronization is important to support time sensitive security mechanisms like Kerberos and also ensures log files have consistent time records across the enterprise, which aids in forensic investigations.'

  tag cis: '2.3.1'
  tag level: 1

  describe.one do
    describe package('chrony') do
      it { should be_installed }
    end

    describe package('ntp') do
      it { should be_installed }
    end
  end

  describe.one do
    describe service('chronyd') do
      it { should be_enabled }
      it { should be_running }
    end

    describe service('chrony') do
      it { should be_enabled }
      it { should be_running }
    end

    describe service('ntpd') do
      it { should be_enabled }
      it { should be_running }
    end

    describe service('ntp') do
      it { should be_enabled }
      it { should be_running }
    end
  end
end

control 'cis-2.3.2' do
  impact 1.0
  title 'Ensure rsyslog is installed and enabled'
  desc 'The rsyslog software is a recommended replacement to the original syslogd daemon which provides improvements over syslogd, such as connection-oriented (i.e. TCP) transmission of logs, the option to log to database formats, and the encryption of log data en route to a central logging server.'
  desc 'rationale', 'The security enhancements of rsyslog such as connection-oriented (i.e. TCP) transmission of logs, the option to log to database formats, and the encryption of log data en route to a central logging server make it a good choice for a centralized logging solution.'

  tag cis: '2.3.2'
  tag level: 1

  describe package('rsyslog') do
    it { should be_installed }
  end

  describe service('rsyslog') do
    it { should be_enabled }
    it { should be_running }
  end
end

# =============================================================================
# Section 6.1 - File Permissions
# =============================================================================

control 'cis-6.1.2' do
  impact 1.0
  title 'Ensure permissions on /etc/passwd are configured'
  desc 'The /etc/passwd file contains user account information that is used by many system utilities and therefore must be readable for these utilities to operate.'
  desc 'rationale', 'It is critical to ensure that the /etc/passwd file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.'

  tag cis: '6.1.2'
  tag level: 1

  describe file('/etc/passwd') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0644' }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

control 'cis-6.1.3' do
  impact 1.0
  title 'Ensure permissions on /etc/shadow are configured'
  desc 'The /etc/shadow file is used to store the information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information.'
  desc 'rationale', 'If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the /etc/shadow file (such as expiration) could also be useful to subvert the user accounts.'

  tag cis: '6.1.3'
  tag level: 1

  describe file('/etc/shadow') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0640' }
    its('owner') { should eq 'root' }
    its('group') { should be_in ['root', 'shadow'] }
  end
end

control 'cis-6.1.4' do
  impact 1.0
  title 'Ensure permissions on /etc/group are configured'
  desc 'The /etc/group file contains a list of all the valid groups defined in the system. The command below allows read/write access for root and read access for everyone else.'
  desc 'rationale', 'The /etc/group file needs to be protected from unauthorized changes by non-privileged users, but needs to be readable as this information is used with many non-privileged programs.'

  tag cis: '6.1.4'
  tag level: 1

  describe file('/etc/group') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0644' }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

control 'cis-6.1.5' do
  impact 1.0
  title 'Ensure permissions on /etc/gshadow are configured'
  desc 'The /etc/gshadow file is used to store the information about groups that is critical to the security of those accounts, such as the hashed password and other security information.'
  desc 'rationale', 'If attackers can gain read access to the /etc/gshadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the /etc/gshadow file (such as group administrators) could also be useful to subvert the group.'

  tag cis: '6.1.5'
  tag level: 1

  describe file('/etc/gshadow') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0640' }
    its('owner') { should eq 'root' }
    its('group') { should be_in ['root', 'shadow'] }
  end
end

control 'cis-6.1.6' do
  impact 1.0
  title 'Ensure permissions on /etc/passwd- are configured'
  desc 'The /etc/passwd- file contains backup user account information.'
  desc 'rationale', 'It is critical to ensure that the /etc/passwd- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.'

  tag cis: '6.1.6'
  tag level: 1

  describe file('/etc/passwd-') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0644' }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

control 'cis-6.1.7' do
  impact 1.0
  title 'Ensure permissions on /etc/shadow- are configured'
  desc 'The /etc/shadow- file is used to store backup information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information.'
  desc 'rationale', 'It is critical to ensure that the /etc/shadow- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.'

  tag cis: '6.1.7'
  tag level: 1

  describe file('/etc/shadow-') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0640' }
    its('owner') { should eq 'root' }
    its('group') { should be_in ['root', 'shadow'] }
  end
end

control 'cis-6.1.8' do
  impact 1.0
  title 'Ensure permissions on /etc/group- are configured'
  desc 'The /etc/group- file contains a backup list of all the valid groups defined in the system.'
  desc 'rationale', 'It is critical to ensure that the /etc/group- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.'

  tag cis: '6.1.8'
  tag level: 1

  describe file('/etc/group-') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0644' }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

control 'cis-6.1.9' do
  impact 1.0
  title 'Ensure permissions on /etc/gshadow- are configured'
  desc 'The /etc/gshadow- file is used to store backup information about groups that is critical to the security of those accounts, such as the hashed password and other security information.'
  desc 'rationale', 'It is critical to ensure that the /etc/gshadow- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.'

  tag cis: '6.1.9'
  tag level: 1

  describe file('/etc/gshadow-') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0640' }
    its('owner') { should eq 'root' }
    its('group') { should be_in ['root', 'shadow'] }
  end
end
