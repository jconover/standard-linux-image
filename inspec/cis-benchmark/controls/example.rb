# encoding: UTF-8
# frozen_string_literal: true

#
# Example control to verify the InSpec profile is working correctly
# This control validates that the target system is Rocky Linux 9 or 10
#

control 'os-verification' do
  impact 1.0
  title 'Verify Operating System'
  desc 'Ensure the target system is running a supported Rocky Linux version (9 or 10)'

  tag 'level': 1
  tag 'benchmark': 'cis-rocky-linux'
  tag 'section': 'prerequisites'

  describe os.family do
    it { should eq 'redhat' }
  end

  describe os.name do
    it { should eq 'rocky' }
  end

  describe os.release.to_i do
    it { should be >= 9 }
    it { should be <= 10 }
  end
end

control 'os-rocky-linux-9-or-10' do
  impact 1.0
  title 'Verify Rocky Linux Version 9 or 10'
  desc 'The system must be running Rocky Linux version 9 or 10 to apply CIS benchmark controls'

  tag 'level': 1
  tag 'benchmark': 'cis-rocky-linux'
  tag 'section': 'prerequisites'

  only_if('This profile is intended for Rocky Linux 9 or 10') do
    os.redhat?
  end

  describe 'Operating System' do
    subject { os }

    its('name') { should eq 'rocky' }
    its('family') { should eq 'redhat' }
  end

  describe 'Rocky Linux Version' do
    subject { os.release.split('.').first.to_i }

    it 'should be version 9 or 10' do
      expect(subject).to be_between(9, 10)
    end
  end
end

control 'profile-test' do
  impact 0.1
  title 'Profile Functionality Test'
  desc 'Simple test to verify the InSpec profile is executing correctly'

  tag 'level': 1
  tag 'benchmark': 'cis-rocky-linux'
  tag 'section': 'test'

  describe 'InSpec Profile' do
    it 'should be able to execute commands' do
      expect(command('echo "InSpec is working"').stdout.strip).to eq 'InSpec is working'
    end

    it 'should be able to read files' do
      expect(file('/etc/os-release')).to exist
    end

    it 'should be able to check services' do
      expect(service('sshd')).to be_installed
    end
  end
end
