# frozen_string_literal: true

# CIS Benchmark Controls for Kernel Parameters
# Sections 1.5 (Kernel Security) and 3.1-3.2 (Network Parameters)

#
# Section 3.1 - Network Parameters (Host Only)
#

control 'cis-3.1.1' do
  impact 1.0
  title 'Ensure IP forwarding is disabled'
  desc 'The net.ipv4.ip_forward flag is used to tell the system whether it can forward packets or not. IP forwarding should be disabled unless the system is a router.'
  tag cis: '3.1.1'
  tag level: 1

  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv6.conf.all.forwarding') do
    its('value') { should eq 0 }
  end
end

control 'cis-3.1.2' do
  impact 1.0
  title 'Ensure packet redirect sending is disabled'
  desc 'ICMP Redirects are used to send routing information to other hosts. As a host itself does not act as a router, there is no need to send redirects.'
  tag cis: '3.1.2'
  tag level: 1

  describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.conf.default.send_redirects') do
    its('value') { should eq 0 }
  end
end

#
# Section 3.2 - Network Parameters (Host and Router)
#

control 'cis-3.2.1' do
  impact 1.0
  title 'Ensure source routed packets are not accepted'
  desc 'In networking, source routing allows a sender to partially or fully specify the route packets take through the network. This can be used to bypass network security measures.'
  tag cis: '3.2.1'
  tag level: 1

  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.conf.default.accept_source_route') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv6.conf.all.accept_source_route') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv6.conf.default.accept_source_route') do
    its('value') { should eq 0 }
  end
end

control 'cis-3.2.2' do
  impact 1.0
  title 'Ensure ICMP redirects are not accepted'
  desc 'ICMP redirect messages are packets that convey routing information and tell your host to send packets via an alternate path. Attackers could use ICMP redirects to alter routing tables.'
  tag cis: '3.2.2'
  tag level: 1

  describe kernel_parameter('net.ipv4.conf.all.accept_redirects') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.conf.default.accept_redirects') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv6.conf.all.accept_redirects') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv6.conf.default.accept_redirects') do
    its('value') { should eq 0 }
  end
end

control 'cis-3.2.3' do
  impact 1.0
  title 'Ensure secure ICMP redirects are not accepted'
  desc 'Secure ICMP redirects are the same as ICMP redirects, except they come from gateways listed on the default gateway list. Even secure redirects can be exploited.'
  tag cis: '3.2.3'
  tag level: 1

  describe kernel_parameter('net.ipv4.conf.all.secure_redirects') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.conf.default.secure_redirects') do
    its('value') { should eq 0 }
  end
end

control 'cis-3.2.4' do
  impact 1.0
  title 'Ensure suspicious packets are logged'
  desc 'When enabled, this feature logs packets with un-routable source addresses to the kernel log. This enables administrators to investigate and take action.'
  tag cis: '3.2.4'
  tag level: 1

  describe kernel_parameter('net.ipv4.conf.all.log_martians') do
    its('value') { should eq 1 }
  end

  describe kernel_parameter('net.ipv4.conf.default.log_martians') do
    its('value') { should eq 1 }
  end
end

control 'cis-3.2.5' do
  impact 1.0
  title 'Ensure broadcast ICMP requests are ignored'
  desc 'Accepting ICMP echo and timestamp requests with broadcast or multicast destinations can be used to trick your host into participating in Smurf attacks.'
  tag cis: '3.2.5'
  tag level: 1

  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its('value') { should eq 1 }
  end
end

control 'cis-3.2.6' do
  impact 1.0
  title 'Ensure bogus ICMP responses are ignored'
  desc 'Some routers violate RFC1122 by sending bogus responses to broadcast frames. Such violations are normally logged, but can fill up the logs.'
  tag cis: '3.2.6'
  tag level: 1

  describe kernel_parameter('net.ipv4.icmp_ignore_bogus_error_responses') do
    its('value') { should eq 1 }
  end
end

control 'cis-3.2.7' do
  impact 1.0
  title 'Ensure Reverse Path Filtering is enabled'
  desc 'Setting net.ipv4.conf.all.rp_filter and net.ipv4.conf.default.rp_filter to 1 forces the Linux kernel to utilize reverse path filtering on a received packet to determine if the packet was valid.'
  tag cis: '3.2.7'
  tag level: 1

  describe kernel_parameter('net.ipv4.conf.all.rp_filter') do
    its('value') { should eq 1 }
  end

  describe kernel_parameter('net.ipv4.conf.default.rp_filter') do
    its('value') { should eq 1 }
  end
end

control 'cis-3.2.8' do
  impact 1.0
  title 'Ensure TCP SYN Cookies is enabled'
  desc 'When tcp_syncookies is set, the kernel will handle TCP SYN packets normally until the half-open connection queue is full, at which time, the SYN cookie functionality kicks in. This provides protection against SYN flood attacks.'
  tag cis: '3.2.8'
  tag level: 1

  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should eq 1 }
  end
end

control 'cis-3.2.9' do
  impact 1.0
  title 'Ensure IPv6 router advertisements are not accepted'
  desc 'This setting disables the systems ability to accept IPv6 router advertisements. Router advertisements can be used to redirect traffic to rogue systems.'
  tag cis: '3.2.9'
  tag level: 1

  describe kernel_parameter('net.ipv6.conf.all.accept_ra') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv6.conf.default.accept_ra') do
    its('value') { should eq 0 }
  end
end

#
# Section 1.5 - Kernel Security
#

control 'cis-1.5.1' do
  impact 1.0
  title 'Ensure address space layout randomization (ASLR) is enabled'
  desc 'Address space layout randomization (ASLR) is an exploit mitigation technique which randomly arranges the address space of key data areas of a process. A value of 2 provides full randomization.'
  tag cis: '1.5.1'
  tag level: 1

  describe kernel_parameter('kernel.randomize_va_space') do
    its('value') { should eq 2 }
  end
end

control 'cis-1.5.2' do
  impact 1.0
  title 'Ensure dmesg is restricted'
  desc 'Setting kernel.dmesg_restrict to 1 restricts access to dmesg output to users with CAP_SYSLOG capability, preventing unprivileged users from reading kernel log messages.'
  tag cis: '1.5.2'
  tag level: 1

  describe kernel_parameter('kernel.dmesg_restrict') do
    its('value') { should eq 1 }
  end
end

control 'cis-1.5.3' do
  impact 1.0
  title 'Ensure kernel pointers are restricted'
  desc 'Setting kernel.kptr_restrict to 1 or 2 restricts kernel pointers from being leaked to unprivileged users. This makes it harder for attackers to locate kernel structures for exploitation.'
  tag cis: '1.5.3'
  tag level: 1

  describe kernel_parameter('kernel.kptr_restrict') do
    its('value') { should cmp >= 1 }
  end
end

control 'cis-1.5.4' do
  impact 1.0
  title 'Ensure ptrace_scope is restricted'
  desc 'Setting kernel.yama.ptrace_scope restricts the ability to use ptrace on processes. A value of 1 or higher prevents unprivileged users from using ptrace to examine or modify other processes.'
  tag cis: '1.5.4'
  tag level: 1

  describe kernel_parameter('kernel.yama.ptrace_scope') do
    its('value') { should cmp >= 1 }
  end
end
