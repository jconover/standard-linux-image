# frozen_string_literal: true

# CIS Benchmark Section 5.2 - SSH Server Configuration
# These controls validate SSH hardening settings per CIS benchmarks

control 'cis-5.2.1' do
  impact 1.0
  title 'Ensure SSH Protocol is set to 2'
  desc 'SSH supports two different and incompatible protocols: SSH1 and SSH2. SSH1 was the original protocol and was subject to security issues. SSH2 is more advanced and secure.'
  desc 'rationale', 'SSH v1 suffers from insecurities that do not affect SSH v2.'
  desc 'check', 'Run the following command and verify that output matches Protocol 2: sshd -T | grep -i protocol'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the parameter as follows: Protocol 2'

  tag cis: 'CIS-5.2.1'
  tag level: 1
  tag server: true
  tag workstation: true

  # Note: Protocol option is deprecated in OpenSSH 7.4+ as only SSH2 is supported
  # This check verifies it's either set to 2 or not present (defaulting to 2)
  describe.one do
    describe sshd_config do
      its('Protocol') { should cmp 2 }
    end
    describe sshd_config do
      its('Protocol') { should be_nil }
    end
  end
end

control 'cis-5.2.2' do
  impact 1.0
  title 'Ensure SSH LogLevel is set to INFO'
  desc 'The INFO parameter specifies that login and logout activity will be logged.'
  desc 'rationale', 'SSH provides several logging levels with varying amounts of verbosity. DEBUG is specifically not recommended other than strictly for debugging SSH communications since it provides so much data that it is difficult to identify important security information. INFO level is the basic level that only records login activity of SSH users.'
  desc 'check', 'Run the following command and verify that output matches LogLevel INFO or LogLevel VERBOSE: sshd -T | grep loglevel'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the parameter as follows: LogLevel INFO'

  tag cis: 'CIS-5.2.2'
  tag level: 1
  tag server: true
  tag workstation: true

  describe sshd_config do
    its('LogLevel') { should cmp(/^(INFO|VERBOSE)$/) }
  end
end

control 'cis-5.2.3' do
  impact 1.0
  title 'Ensure SSH X11Forwarding is disabled'
  desc 'The X11Forwarding parameter provides the ability to tunnel X11 traffic through the connection to enable remote graphic connections.'
  desc 'rationale', 'Disable X11 forwarding unless there is an operational requirement to use X11 applications directly. There is a small risk that the remote X11 servers of users who are logged in via SSH with X11 forwarding could be compromised by other users on the X11 server.'
  desc 'check', 'Run the following command and verify that output matches X11Forwarding no: sshd -T | grep x11forwarding'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the parameter as follows: X11Forwarding no'

  tag cis: 'CIS-5.2.3'
  tag level: 1
  tag server: true
  tag workstation: true

  describe sshd_config do
    its('X11Forwarding') { should cmp 'no' }
  end
end

control 'cis-5.2.4' do
  impact 1.0
  title 'Ensure SSH MaxAuthTries is set to 4 or less'
  desc 'The MaxAuthTries parameter specifies the maximum number of authentication attempts permitted per connection.'
  desc 'rationale', 'Setting the MaxAuthTries parameter to a low number will minimize the risk of successful brute force attacks to the SSH server. While the recommended setting is 4, set the number based on site policy.'
  desc 'check', 'Run the following command and verify that output MaxAuthTries is 4 or less: sshd -T | grep maxauthtries'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the parameter as follows: MaxAuthTries 4'

  tag cis: 'CIS-5.2.4'
  tag level: 1
  tag server: true
  tag workstation: true

  describe sshd_config do
    its('MaxAuthTries') { should cmp <= 4 }
  end
end

control 'cis-5.2.5' do
  impact 1.0
  title 'Ensure SSH IgnoreRhosts is enabled'
  desc 'The IgnoreRhosts parameter specifies that .rhosts and .shosts files will not be used in RhostsRSAAuthentication or HostbasedAuthentication.'
  desc 'rationale', 'Setting this parameter forces users to enter a password when authenticating with SSH.'
  desc 'check', 'Run the following command and verify that output matches IgnoreRhosts yes: sshd -T | grep ignorerhosts'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the parameter as follows: IgnoreRhosts yes'

  tag cis: 'CIS-5.2.5'
  tag level: 1
  tag server: true
  tag workstation: true

  describe sshd_config do
    its('IgnoreRhosts') { should cmp 'yes' }
  end
end

control 'cis-5.2.6' do
  impact 1.0
  title 'Ensure SSH HostbasedAuthentication is disabled'
  desc 'The HostbasedAuthentication parameter specifies if authentication is allowed through trusted hosts via the user of .rhosts, or /etc/hosts.equiv, along with successful public key client host authentication.'
  desc 'rationale', 'Even though .rhosts files are ineffective if support is disabled in /etc/pam.conf, disabling the ability to use .rhosts files in SSH provides an additional layer of protection.'
  desc 'check', 'Run the following command and verify that output matches HostbasedAuthentication no: sshd -T | grep hostbasedauthentication'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the parameter as follows: HostbasedAuthentication no'

  tag cis: 'CIS-5.2.6'
  tag level: 1
  tag server: true
  tag workstation: true

  describe sshd_config do
    its('HostbasedAuthentication') { should cmp 'no' }
  end
end

control 'cis-5.2.7' do
  impact 1.0
  title 'Ensure SSH root login is disabled'
  desc 'The PermitRootLogin parameter specifies if the root user can log in using SSH.'
  desc 'rationale', 'Disallowing root logins over SSH requires system admins to authenticate using their own individual account, then escalating to root via sudo or su. This in turn limits opportunity for non-repudiation and provides a clear audit trail.'
  desc 'check', 'Run the following command and verify that output matches PermitRootLogin no: sshd -T | grep permitrootlogin'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the parameter as follows: PermitRootLogin no'

  tag cis: 'CIS-5.2.7'
  tag level: 1
  tag server: true
  tag workstation: true

  describe sshd_config do
    its('PermitRootLogin') { should cmp 'no' }
  end
end

control 'cis-5.2.8' do
  impact 1.0
  title 'Ensure SSH PermitEmptyPasswords is disabled'
  desc 'The PermitEmptyPasswords parameter specifies if the SSH server allows login to accounts with empty password strings.'
  desc 'rationale', 'Disallowing remote shell access to accounts that have an empty password reduces the probability of unauthorized access to the system.'
  desc 'check', 'Run the following command and verify that output matches PermitEmptyPasswords no: sshd -T | grep permitemptypasswords'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the parameter as follows: PermitEmptyPasswords no'

  tag cis: 'CIS-5.2.8'
  tag level: 1
  tag server: true
  tag workstation: true

  describe sshd_config do
    its('PermitEmptyPasswords') { should cmp 'no' }
  end
end

control 'cis-5.2.9' do
  impact 1.0
  title 'Ensure SSH PermitUserEnvironment is disabled'
  desc 'The PermitUserEnvironment option allows users to present environment options to the SSH daemon.'
  desc 'rationale', 'Permitting users the ability to set environment variables through the SSH daemon could potentially allow users to bypass security controls (e.g. setting an execution path that has SSH to them bypassing LD_LIBRARY_PATH).'
  desc 'check', 'Run the following command and verify that output matches PermitUserEnvironment no: sshd -T | grep permituserenvironment'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the parameter as follows: PermitUserEnvironment no'

  tag cis: 'CIS-5.2.9'
  tag level: 1
  tag server: true
  tag workstation: true

  describe sshd_config do
    its('PermitUserEnvironment') { should cmp 'no' }
  end
end

control 'cis-5.2.10' do
  impact 1.0
  title 'Ensure only strong Ciphers are used'
  desc 'This variable limits the ciphers that SSH can use during communication.'
  desc 'rationale', 'Weak ciphers that are used for authentication to the cryptographic module cannot be relied upon to provide confidentiality or integrity, and system data may be compromised.'
  desc 'check', 'Run the following command and verify that output does not contain any weak ciphers: sshd -T | grep ciphers'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the Ciphers parameter to use strong ciphers only.'

  tag cis: 'CIS-5.2.10'
  tag level: 1
  tag server: true
  tag workstation: true

  # Weak ciphers that should not be used
  weak_ciphers = [
    '3des-cbc',
    'aes128-cbc',
    'aes192-cbc',
    'aes256-cbc',
    'arcfour',
    'arcfour128',
    'arcfour256',
    'blowfish-cbc',
    'cast128-cbc',
    'rijndael-cbc@lysator.liu.se'
  ]

  describe sshd_config do
    its('Ciphers') { should_not be_nil }
  end

  weak_ciphers.each do |cipher|
    describe sshd_config do
      its('Ciphers') { should_not include cipher }
    end
  end
end

control 'cis-5.2.11' do
  impact 1.0
  title 'Ensure only strong MAC algorithms are used'
  desc 'This variable limits the MAC algorithms that SSH can use during communication.'
  desc 'rationale', 'MD5 and 96-bit MAC algorithms are considered weak and have been shown to increase exploitability in SSH downgrade attacks. Weak algorithms continue to have a great deal of attention as a weak spot that can be exploited with expanded computing power.'
  desc 'check', 'Run the following command and verify that output does not contain any weak MAC algorithms: sshd -T | grep -i macs'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the MACs parameter to use strong MAC algorithms only.'

  tag cis: 'CIS-5.2.11'
  tag level: 1
  tag server: true
  tag workstation: true

  # Weak MAC algorithms that should not be used
  weak_macs = [
    'hmac-md5',
    'hmac-md5-96',
    'hmac-ripemd160',
    'hmac-sha1',
    'hmac-sha1-96',
    'umac-64@openssh.com',
    'umac-128@openssh.com',
    'hmac-md5-etm@openssh.com',
    'hmac-md5-96-etm@openssh.com',
    'hmac-ripemd160-etm@openssh.com',
    'hmac-sha1-etm@openssh.com',
    'hmac-sha1-96-etm@openssh.com',
    'umac-64-etm@openssh.com'
  ]

  describe sshd_config do
    its('MACs') { should_not be_nil }
  end

  weak_macs.each do |mac|
    describe sshd_config do
      its('MACs') { should_not include mac }
    end
  end
end

control 'cis-5.2.12' do
  impact 1.0
  title 'Ensure only strong Key Exchange algorithms are used'
  desc 'Key exchange is any method in cryptography by which cryptographic keys are exchanged between two parties, allowing use of a cryptographic algorithm.'
  desc 'rationale', 'Key exchange methods that are considered weak should be removed. A key exchange method may be weak because too few bits are used, or the hashing algorithm is considered too weak. Using weak algorithms could expose connections to man-in-the-middle attacks.'
  desc 'check', 'Run the following command and verify that output does not contain any weak key exchange algorithms: sshd -T | grep kexalgorithms'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the KexAlgorithms parameter to use strong key exchange algorithms only.'

  tag cis: 'CIS-5.2.12'
  tag level: 1
  tag server: true
  tag workstation: true

  # Weak key exchange algorithms that should not be used
  weak_kex = [
    'diffie-hellman-group1-sha1',
    'diffie-hellman-group14-sha1',
    'diffie-hellman-group-exchange-sha1',
    'ecdh-sha2-nistp256',
    'ecdh-sha2-nistp384',
    'ecdh-sha2-nistp521'
  ]

  describe sshd_config do
    its('KexAlgorithms') { should_not be_nil }
  end

  weak_kex.each do |kex|
    describe sshd_config do
      its('KexAlgorithms') { should_not include kex }
    end
  end
end

control 'cis-5.2.13' do
  impact 1.0
  title 'Ensure SSH LoginGraceTime is set to 60 seconds or less'
  desc 'The LoginGraceTime parameter specifies the time allowed for successful authentication to the SSH server.'
  desc 'rationale', 'Setting the LoginGraceTime parameter to a low number will minimize the risk of successful brute force attacks to the SSH server. It will also limit the number of concurrent unauthenticated connections.'
  desc 'check', 'Run the following command and verify that output matches LoginGraceTime is 60 or less: sshd -T | grep logingracetime'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the parameter as follows: LoginGraceTime 60'

  tag cis: 'CIS-5.2.13'
  tag level: 1
  tag server: true
  tag workstation: true

  describe sshd_config do
    its('LoginGraceTime') { should cmp <= 60 }
  end
end

control 'cis-5.2.14' do
  impact 1.0
  title 'Ensure SSH access is limited'
  desc 'There are several options available to limit which users and groups can access the system via SSH. It is recommended that at least one of the following options be used: AllowUsers, AllowGroups, DenyUsers, DenyGroups.'
  desc 'rationale', 'Restricting which users can remotely access the system via SSH will help ensure that only authorized users access the system.'
  desc 'check', 'Run the following commands and verify that output matches for at least one: sshd -T | grep allowusers, sshd -T | grep allowgroups, sshd -T | grep denyusers, sshd -T | grep denygroups'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set one or more of the parameters as follows: AllowUsers <userlist>, AllowGroups <grouplist>, DenyUsers <userlist>, DenyGroups <grouplist>'

  tag cis: 'CIS-5.2.14'
  tag level: 1
  tag server: true
  tag workstation: true

  describe.one do
    describe sshd_config do
      its('AllowUsers') { should_not be_nil }
    end
    describe sshd_config do
      its('AllowGroups') { should_not be_nil }
    end
    describe sshd_config do
      its('DenyUsers') { should_not be_nil }
    end
    describe sshd_config do
      its('DenyGroups') { should_not be_nil }
    end
  end
end

control 'cis-5.2.15' do
  impact 1.0
  title 'Ensure SSH warning banner is configured'
  desc 'The Banner parameter specifies a file whose contents must be sent to the remote user before authentication is permitted.'
  desc 'rationale', 'Banners are used to warn connecting users of the particular sites policy regarding connection. Presenting a warning message prior to the normal user login may assist the prosecution of trespassers on the computer system.'
  desc 'check', 'Run the following command and verify that output matches Banner /etc/issue.net: sshd -T | grep banner'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the parameter as follows: Banner /etc/issue.net'

  tag cis: 'CIS-5.2.15'
  tag level: 1
  tag server: true
  tag workstation: true

  describe sshd_config do
    its('Banner') { should_not be_nil }
    its('Banner') { should_not cmp 'none' }
  end

  describe file(sshd_config.Banner) do
    it { should exist }
  end
end

control 'cis-5.2.16' do
  impact 1.0
  title 'Ensure SSH MaxStartups is configured'
  desc 'The MaxStartups parameter specifies the maximum number of concurrent unauthenticated connections to the SSH daemon.'
  desc 'rationale', 'To protect a system from denial of service due to a large number of pending authentication connection attempts, use the rate limiting function of MaxStartups to protect availability of sshd logins and prevent overwhelming the daemon.'
  desc 'check', 'Run the following command and verify that output MaxStartups is 10:30:60 or more restrictive: sshd -T | grep maxstartups'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the parameter as follows: MaxStartups 10:30:60'

  tag cis: 'CIS-5.2.16'
  tag level: 1
  tag server: true
  tag workstation: true

  # MaxStartups can be specified as a single integer or as start:rate:full
  # Recommended: 10:30:60 or more restrictive
  describe sshd_config do
    its('MaxStartups') { should_not be_nil }
  end

  # Parse MaxStartups value - it should be in format start:rate:full or a single number
  maxstartups = sshd_config.MaxStartups

  if maxstartups =~ /:/
    # Format: start:rate:full
    parts = maxstartups.split(':')
    describe 'MaxStartups start value' do
      subject { parts[0].to_i }
      it { should cmp <= 10 }
    end
    describe 'MaxStartups rate value' do
      subject { parts[1].to_i }
      it { should cmp <= 30 }
    end
    describe 'MaxStartups full value' do
      subject { parts[2].to_i }
      it { should cmp <= 60 }
    end
  else
    # Single integer format
    describe 'MaxStartups value' do
      subject { maxstartups.to_i }
      it { should cmp <= 10 }
    end
  end
end

control 'cis-5.2.17' do
  impact 1.0
  title 'Ensure SSH MaxSessions is limited'
  desc 'The MaxSessions parameter specifies the maximum number of open sessions permitted from a given connection.'
  desc 'rationale', 'To protect a system from denial of service due to a large number of concurrent sessions, use the MaxSessions parameter to limit the number of sessions per connection.'
  desc 'check', 'Run the following command and verify that output MaxSessions is 10 or less: sshd -T | grep maxsessions'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the parameter as follows: MaxSessions 10'

  tag cis: 'CIS-5.2.17'
  tag level: 1
  tag server: true
  tag workstation: true

  describe sshd_config do
    its('MaxSessions') { should cmp <= 10 }
  end
end

control 'cis-5.2.18' do
  impact 1.0
  title 'Ensure SSH Idle Timeout Interval is configured'
  desc 'The two options ClientAliveInterval and ClientAliveCountMax control the timeout of SSH sessions.'
  desc 'rationale', 'Having no timeout value associated with a connection could allow an unauthorized user access to another users SSH session. Setting a timeout value reduces this risk. ClientAliveInterval - Sets a timeout interval in seconds after which if no data has been received from the client, sshd will send a message through the encrypted channel to request a response from the client. ClientAliveCountMax - Sets the number of client alive messages which may be sent without sshd receiving any messages back from the client.'
  desc 'check', 'Run the following command and verify ClientAliveInterval is 300 or less and ClientAliveCountMax is 3 or less: sshd -T | grep clientalive'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file to set the parameters as follows: ClientAliveInterval 300, ClientAliveCountMax 3'

  tag cis: 'CIS-5.2.18'
  tag level: 1
  tag server: true
  tag workstation: true

  describe sshd_config do
    its('ClientAliveInterval') { should cmp <= 300 }
    its('ClientAliveInterval') { should cmp > 0 }
  end

  describe sshd_config do
    its('ClientAliveCountMax') { should cmp <= 3 }
  end
end
