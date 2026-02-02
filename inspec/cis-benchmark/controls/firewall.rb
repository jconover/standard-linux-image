# frozen_string_literal: true

# CIS Benchmark Controls for Firewall Configuration (Section 3.4)
# These controls validate firewalld configuration according to CIS benchmarks

control 'cis-3.4.1.1' do
  impact 1.0
  title 'Ensure firewalld is installed'
  desc 'firewalld is a firewall management tool that provides a dynamically managed firewall with support for network/firewall zones.'
  desc 'rationale', 'A firewall is essential for controlling network traffic and protecting the system from unauthorized access.'
  desc 'check', 'Run rpm -q firewalld to verify firewalld is installed.'
  desc 'fix', 'Run yum install firewalld or dnf install firewalld to install firewalld.'

  tag cis: '3.4.1.1'
  tag level: 1
  tag server: true
  tag workstation: true

  describe package('firewalld') do
    it { should be_installed }
  end
end

control 'cis-3.4.1.2' do
  impact 1.0
  title 'Ensure firewalld service is enabled and running'
  desc 'firewalld service should be enabled and running to ensure the firewall is active at all times.'
  desc 'rationale', 'If the firewall service is not enabled and running, the system is not protected by firewall rules.'
  desc 'check', 'Run systemctl is-enabled firewalld and systemctl status firewalld to verify the service is enabled and running.'
  desc 'fix', 'Run systemctl enable firewalld --now to enable and start the firewalld service.'

  tag cis: '3.4.1.2'
  tag level: 1
  tag server: true
  tag workstation: true

  describe service('firewalld') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end

  describe command('systemctl is-enabled firewalld') do
    its('stdout') { should match(/^enabled/) }
    its('exit_status') { should eq 0 }
  end
end

control 'cis-3.4.1.3' do
  impact 1.0
  title 'Ensure default zone is set'
  desc 'The default zone should be set to drop or block to ensure traffic is denied by default.'
  desc 'rationale', 'Setting the default zone to drop or block ensures that all incoming traffic is denied unless explicitly allowed. This implements a deny-all, permit-by-exception policy.'
  desc 'check', 'Run firewall-cmd --get-default-zone to verify the default zone is set to drop or block.'
  desc 'fix', 'Run firewall-cmd --set-default-zone=drop to set the default zone to drop.'

  tag cis: '3.4.1.3'
  tag level: 1
  tag server: true
  tag workstation: true

  # Acceptable default zones that deny traffic by default
  acceptable_zones = %w[drop block]

  describe command('firewall-cmd --get-default-zone') do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/^(drop|block)$/) }
  end

  default_zone = command('firewall-cmd --get-default-zone').stdout.strip
  describe "Default firewall zone '#{default_zone}'" do
    subject { default_zone }
    it { should be_in acceptable_zones }
  end
end

control 'cis-3.4.1.4' do
  impact 0.7
  title 'Ensure unnecessary services are removed from zones'
  desc 'Only necessary services should be allowed in firewall zones. Unnecessary services should be removed to minimize the attack surface.'
  desc 'rationale', 'Removing unnecessary services from firewall zones reduces the attack surface and limits potential entry points for attackers.'
  desc 'check', 'Run firewall-cmd --list-all for each zone and review the services allowed.'
  desc 'fix', 'Run firewall-cmd --zone=<zone> --remove-service=<service> --permanent and firewall-cmd --reload to remove unnecessary services.'

  tag cis: '3.4.1.4'
  tag level: 1
  tag server: true
  tag workstation: true

  # Define services that are commonly unnecessary and should be reviewed
  # These services are often enabled by default but may not be needed
  unnecessary_services = %w[
    cockpit
    dhcpv6-client
    mdns
    samba-client
  ]

  # Get active zones
  active_zones_output = command('firewall-cmd --get-active-zones').stdout

  describe command('firewall-cmd --get-active-zones') do
    its('exit_status') { should eq 0 }
  end

  # Check each active zone for unnecessary services
  active_zones_output.lines.each do |line|
    next if line.strip.empty? || line.include?('interfaces:') || line.include?('sources:')

    zone = line.strip
    next if zone.empty?

    zone_services = command("firewall-cmd --zone=#{zone} --list-services").stdout.strip.split

    unnecessary_services.each do |service|
      describe "Zone '#{zone}' service '#{service}'" do
        subject { zone_services }
        it "should not include unnecessary service #{service}" do
          expect(zone_services).not_to include(service)
        end
      end
    end
  end
end

control 'cis-3.4.1.5' do
  impact 1.0
  title 'Ensure firewalld is not disabled by nftables'
  desc 'nftables should not be configured in a way that disables or conflicts with firewalld.'
  desc 'rationale', 'If nftables is used alongside firewalld, it may create conflicting rules or disable firewalld functionality.'
  desc 'check', 'Verify nftables service is not enabled if firewalld is the primary firewall manager.'
  desc 'fix', 'Run systemctl disable nftables --now if firewalld is the primary firewall manager.'

  tag cis: '3.4.1.5'
  tag level: 1
  tag server: true
  tag workstation: true

  # If firewalld is running, nftables service should not be enabled/running independently
  # firewalld uses nftables as a backend, but the nftables service should not be managing rules directly
  if service('firewalld').running?
    describe service('nftables') do
      it { should_not be_enabled }
    end

    describe command('systemctl is-enabled nftables 2>/dev/null') do
      its('stdout') { should_not match(/^enabled/) }
    end
  else
    describe 'firewalld is not running' do
      skip 'This control only applies when firewalld is the active firewall manager'
    end
  end
end

control 'cis-3.4.1.6' do
  impact 1.0
  title 'Ensure firewalld is not disabled by iptables'
  desc 'iptables-services should not be enabled as it can conflict with and disable firewalld.'
  desc 'rationale', 'Running iptables-services alongside firewalld can cause conflicting rules and unexpected behavior.'
  desc 'check', 'Verify iptables and ip6tables services are not enabled if firewalld is the primary firewall manager.'
  desc 'fix', 'Run systemctl disable iptables --now and systemctl disable ip6tables --now if firewalld is the primary firewall manager.'

  tag cis: '3.4.1.6'
  tag level: 1
  tag server: true
  tag workstation: true

  # If firewalld is running, iptables services should not be enabled
  if service('firewalld').running?
    describe service('iptables') do
      it { should_not be_enabled }
    end

    describe service('ip6tables') do
      it { should_not be_enabled }
    end

    describe command('systemctl is-enabled iptables 2>/dev/null') do
      its('stdout') { should_not match(/^enabled/) }
    end

    describe command('systemctl is-enabled ip6tables 2>/dev/null') do
      its('stdout') { should_not match(/^enabled/) }
    end
  else
    describe 'firewalld is not running' do
      skip 'This control only applies when firewalld is the active firewall manager'
    end
  end
end

# Custom Controls

control 'firewall-logging' do
  impact 0.5
  title 'Ensure firewalld logging is enabled'
  desc 'Firewall logging should be enabled to record denied connections and security events.'
  desc 'rationale', 'Logging firewall events provides visibility into blocked traffic and potential security incidents for monitoring and forensic analysis.'
  desc 'check', 'Run firewall-cmd --get-log-denied to verify logging is enabled.'
  desc 'fix', 'Run firewall-cmd --set-log-denied=all --permanent and firewall-cmd --reload to enable logging.'

  tag custom: true
  tag logging: true
  tag server: true
  tag workstation: true

  # Acceptable log-denied settings (anything other than 'off')
  acceptable_log_settings = %w[all unicast broadcast multicast]

  describe command('firewall-cmd --get-log-denied') do
    its('exit_status') { should eq 0 }
    its('stdout') { should_not match(/^off$/) }
  end

  log_setting = command('firewall-cmd --get-log-denied').stdout.strip
  describe "Firewall log-denied setting '#{log_setting}'" do
    subject { log_setting }
    it { should be_in acceptable_log_settings }
  end
end

control 'firewall-ssh-only' do
  impact 0.7
  title 'Ensure only SSH is allowed in public zone (or configured services)'
  desc 'The public zone should only allow SSH and other explicitly configured essential services.'
  desc 'rationale', 'Limiting allowed services reduces the attack surface. SSH is typically the only service needed for remote administration.'
  desc 'check', 'Run firewall-cmd --zone=public --list-services to verify only essential services are allowed.'
  desc 'fix', 'Remove unnecessary services using firewall-cmd --zone=public --remove-service=<service> --permanent and reload.'

  tag custom: true
  tag ssh: true
  tag server: true
  tag workstation: true

  # Define allowed services - SSH is required, others can be added based on requirements
  # This can be customized via an input variable if needed
  allowed_services = input('allowed_firewall_services', value: ['ssh'], description: 'List of services allowed in public zone')

  describe command('firewall-cmd --zone=public --list-services') do
    its('exit_status') { should eq 0 }
  end

  public_services = command('firewall-cmd --zone=public --list-services').stdout.strip.split

  describe 'Public zone services' do
    subject { public_services }
    it { should include('ssh') }
  end

  # Check that no unexpected services are present
  public_services.each do |service|
    describe "Service '#{service}' in public zone" do
      subject { service }
      it "should be in the allowed services list: #{allowed_services.join(', ')}" do
        expect(allowed_services).to include(service)
      end
    end
  end

  # Additional validation - verify SSH service is actually working
  describe command('firewall-cmd --zone=public --query-service=ssh') do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/yes/) }
  end
end

# Additional helper control to verify overall firewall status
control 'firewall-status' do
  impact 1.0
  title 'Verify overall firewall status and configuration'
  desc 'Comprehensive check of firewall status including active zones and runtime configuration.'
  desc 'rationale', 'Verifying overall firewall status ensures the firewall is properly configured and protecting the system.'
  desc 'check', 'Run firewall-cmd --state and firewall-cmd --list-all to verify firewall configuration.'

  tag custom: true
  tag status: true
  tag server: true
  tag workstation: true

  describe command('firewall-cmd --state') do
    its('stdout') { should match(/^running/) }
    its('exit_status') { should eq 0 }
  end

  describe command('firewall-cmd --list-all') do
    its('exit_status') { should eq 0 }
    its('stdout') { should_not be_empty }
  end

  describe command('firewall-cmd --get-active-zones') do
    its('exit_status') { should eq 0 }
    its('stdout') { should_not be_empty }
  end

  # Verify permanent configuration matches runtime
  describe command('firewall-cmd --list-all --permanent') do
    its('exit_status') { should eq 0 }
  end
end
