# frozen_string_literal: true

# CIS Benchmark Controls for PAM and Password Validation
# Sections 5.3 (Configure PAM) and 5.4 (User Accounts and Environment)

# ------------------------------------------------------------------------------
# Section 5.3 - Configure PAM
# ------------------------------------------------------------------------------

control 'cis-5.3.1' do
  impact 1.0
  title 'Ensure password creation requirements are configured'
  desc 'The pam_pwquality module checks the strength of passwords. It performs
        checks such as making sure a password is not a dictionary word, it is a
        certain length, contains a mix of characters, and more.'
  desc 'rationale', 'Strong passwords protect systems from being hacked through
        brute force methods.'
  desc 'check', 'Review /etc/security/pwquality.conf and ensure password
        complexity requirements are configured.'

  tag cis: '5.3.1'
  tag level: 1

  ref 'CIS Benchmark', url: 'https://www.cisecurity.org/cis-benchmarks'

  pwquality_conf = '/etc/security/pwquality.conf'

  describe file(pwquality_conf) do
    it { should exist }
    it { should be_file }
  end

  if file(pwquality_conf).exist?
    pwquality = parse_config_file(pwquality_conf)

    describe 'Password minimum length (minlen)' do
      subject { pwquality.params['minlen'].to_i }
      it { should cmp >= 14 }
    end

    describe 'Password minimum character classes (minclass)' do
      subject { pwquality.params['minclass'].to_i }
      it { should cmp >= 4 }
    end

    describe 'Password digit requirement (dcredit)' do
      subject { pwquality.params['dcredit'].to_i }
      it { should cmp <= -1 }
    end

    describe 'Password uppercase requirement (ucredit)' do
      subject { pwquality.params['ucredit'].to_i }
      it { should cmp <= -1 }
    end

    describe 'Password lowercase requirement (lcredit)' do
      subject { pwquality.params['lcredit'].to_i }
      it { should cmp <= -1 }
    end

    describe 'Password special character requirement (ocredit)' do
      subject { pwquality.params['ocredit'].to_i }
      it { should cmp <= -1 }
    end

    describe 'Password maximum consecutive repeating characters (maxrepeat)' do
      subject { pwquality.params['maxrepeat'].to_i }
      it { should cmp <= 3 }
      it { should cmp > 0 }
    end

    describe 'Password maximum consecutive same class characters (maxclassrepeat)' do
      subject { pwquality.params['maxclassrepeat'].to_i }
      it { should cmp <= 4 }
      it { should cmp > 0 }
    end

    describe 'Password dictionary check (dictcheck)' do
      subject { pwquality.params['dictcheck'].to_i }
      it { should cmp >= 1 }
    end

    describe 'Password username check (usercheck)' do
      subject { pwquality.params['usercheck'].to_i }
      it { should cmp >= 1 }
    end

    describe 'Enforce for root user (enforce_for_root)' do
      subject { pwquality.params['enforce_for_root'] }
      it { should_not be_nil }
    end
  end
end

control 'cis-5.3.2' do
  impact 1.0
  title 'Ensure lockout for failed password attempts is configured'
  desc 'Lock out users after n unsuccessful consecutive login attempts using
        pam_faillock. The first sets of changes are made to the PAM configuration
        files. The second set of changes are made to the faillock configuration.'
  desc 'rationale', 'Locking out user IDs after n unsuccessful consecutive login
        attempts mitigates brute force password attacks against your systems.'
  desc 'check', 'Review /etc/security/faillock.conf and PAM configuration files
        to ensure faillock is properly configured.'

  tag cis: '5.3.2'
  tag level: 1

  ref 'CIS Benchmark', url: 'https://www.cisecurity.org/cis-benchmarks'

  faillock_conf = '/etc/security/faillock.conf'

  describe file(faillock_conf) do
    it { should exist }
    it { should be_file }
  end

  if file(faillock_conf).exist?
    faillock = parse_config_file(faillock_conf)

    describe 'Faillock deny (number of failed attempts before lockout)' do
      subject { faillock.params['deny'].to_i }
      it { should cmp <= 5 }
      it { should cmp > 0 }
    end

    describe 'Faillock unlock_time (lockout duration in seconds)' do
      subject { faillock.params['unlock_time'].to_i }
      # 0 means the account is locked until manually unlocked
      # Otherwise should be at least 900 seconds (15 minutes)
      it { should satisfy { |v| v == 0 || v >= 900 } }
    end

    describe 'Faillock fail_interval (period during which failures are counted)' do
      subject { faillock.params['fail_interval'].to_i }
      it { should cmp >= 900 }
    end

    describe 'Faillock even_deny_root' do
      subject { faillock.params['even_deny_root'] }
      it { should_not be_nil }
    end

    describe 'Faillock root_unlock_time' do
      subject { faillock.params['root_unlock_time'].to_i }
      it { should cmp >= 60 }
    end
  end

  # Check PAM configuration for faillock
  %w[/etc/pam.d/system-auth /etc/pam.d/password-auth].each do |pam_file|
    if file(pam_file).exist?
      describe file(pam_file) do
        its('content') { should match(/pam_faillock\.so/) }
      end

      describe "#{pam_file} faillock preauth" do
        subject { file(pam_file).content }
        it { should match(/auth\s+required\s+pam_faillock\.so\s+preauth/) }
      end

      describe "#{pam_file} faillock authfail" do
        subject { file(pam_file).content }
        it { should match(/auth\s+\[default=die\]\s+pam_faillock\.so\s+authfail/) }
      end

      describe "#{pam_file} faillock authsucc" do
        subject { file(pam_file).content }
        it { should match(/auth\s+sufficient\s+pam_faillock\.so\s+authsucc/) }
      end
    end
  end
end

control 'cis-5.3.3' do
  impact 1.0
  title 'Ensure password reuse is limited'
  desc 'The pam_pwhistory module saves the last passwords for each user in order
        to force password change history and keep the user from alternating
        between the same password too frequently.'
  desc 'rationale', 'Forcing users not to reuse their past 24 passwords make it
        less likely that an attacker will be able to guess the password.'
  desc 'check', 'Review PAM configuration to ensure password history is enforced.'

  tag cis: '5.3.3'
  tag level: 1

  ref 'CIS Benchmark', url: 'https://www.cisecurity.org/cis-benchmarks'

  # Check for pam_pwhistory in PAM configuration files
  pam_files = %w[
    /etc/pam.d/system-auth
    /etc/pam.d/password-auth
  ]

  pwhistory_configured = false

  pam_files.each do |pam_file|
    next unless file(pam_file).exist?

    describe file(pam_file) do
      it { should exist }
    end

    content = file(pam_file).content

    # Check for pam_pwhistory.so
    if content.match?(/pam_pwhistory\.so/)
      pwhistory_configured = true

      describe "#{pam_file} pam_pwhistory configuration" do
        subject { content }
        it { should match(/password\s+.*pam_pwhistory\.so/) }
      end

      # Extract remember value
      remember_match = content.match(/pam_pwhistory\.so.*remember=(\d+)/)
      if remember_match
        describe "#{pam_file} password history (remember)" do
          subject { remember_match[1].to_i }
          it { should cmp >= 24 }
        end
      end

      # Check for enforce_for_root
      describe "#{pam_file} pam_pwhistory enforce_for_root" do
        subject { content }
        it { should match(/pam_pwhistory\.so.*enforce_for_root/) }
      end

      # Check use_authtok is set
      describe "#{pam_file} pam_pwhistory use_authtok" do
        subject { content }
        it { should match(/pam_pwhistory\.so.*use_authtok/) }
      end
    end
  end

  # Also check pwhistory.conf if it exists (RHEL 9+)
  pwhistory_conf = '/etc/security/pwhistory.conf'
  if file(pwhistory_conf).exist?
    pwhistory_configured = true

    describe file(pwhistory_conf) do
      it { should exist }
    end

    pwhistory = parse_config_file(pwhistory_conf)

    describe 'Password history remember value' do
      subject { pwhistory.params['remember'].to_i }
      it { should cmp >= 24 }
    end

    describe 'Password history enforce_for_root' do
      subject { pwhistory.params['enforce_for_root'] }
      it { should_not be_nil }
    end
  end

  describe 'pam_pwhistory should be configured' do
    subject { pwhistory_configured }
    it { should be true }
  end
end

control 'cis-5.3.4' do
  impact 1.0
  title 'Ensure password hashing algorithm is SHA-512'
  desc 'The commands below change password encryption from md5 to sha512 (a much
        stronger hashing algorithm). All existing accounts will need to perform
        a password change to upgrade the stored hashes to the new algorithm.'
  desc 'rationale', 'The SHA-512 algorithm provides much stronger hashing than MD5,
        thus providing additional protection to the system by increasing the level
        of effort for an attacker to successfully determine passwords.'
  desc 'check', 'Review /etc/login.defs and PAM configuration for password hashing
        algorithm settings.'

  tag cis: '5.3.4'
  tag level: 1

  ref 'CIS Benchmark', url: 'https://www.cisecurity.org/cis-benchmarks'

  # Check /etc/login.defs
  describe login_defs do
    its('ENCRYPT_METHOD') { should eq 'SHA512' }
  end

  # Check PAM configuration files
  pam_files = %w[
    /etc/pam.d/system-auth
    /etc/pam.d/password-auth
  ]

  pam_files.each do |pam_file|
    next unless file(pam_file).exist?

    describe file(pam_file) do
      it { should exist }
    end

    describe "#{pam_file} password hashing algorithm" do
      subject { file(pam_file).content }
      it { should match(/password\s+.*pam_unix\.so.*sha512/) }
    end
  end

  # Check libuser.conf if it exists
  libuser_conf = '/etc/libuser.conf'
  if file(libuser_conf).exist?
    describe parse_config_file(libuser_conf) do
      its(['defaults', 'crypt_style']) { should eq 'sha512' }
    end
  end
end

# ------------------------------------------------------------------------------
# Section 5.4.1 - Shadow Password Suite Parameters
# ------------------------------------------------------------------------------

control 'cis-5.4.1.1' do
  impact 1.0
  title 'Ensure password expiration is 365 days or less'
  desc 'The PASS_MAX_DAYS parameter in /etc/login.defs allows an administrator to
        force passwords to expire once they reach a defined age. It is recommended
        that the PASS_MAX_DAYS parameter be set to less than or equal to 365 days.'
  desc 'rationale', 'The window of opportunity for an attacker to leverage compromised
        credentials or successfully compromise credentials via an online brute
        force attack is limited by the age of the password.'
  desc 'check', 'Verify PASS_MAX_DAYS is 365 or less in /etc/login.defs and for
        all users in /etc/shadow.'

  tag cis: '5.4.1.1'
  tag level: 1

  ref 'CIS Benchmark', url: 'https://www.cisecurity.org/cis-benchmarks'

  describe login_defs do
    its('PASS_MAX_DAYS') { should cmp <= 365 }
    its('PASS_MAX_DAYS') { should cmp > 0 }
  end

  # Check all users with passwords
  shadow_file = '/etc/shadow'

  if file(shadow_file).exist?
    shadow(shadow_file).users.each do |user|
      user_entry = shadow(shadow_file).filter(user: user)
      max_days = user_entry.max_days.first

      # Skip users with no password or locked accounts
      next if user_entry.passwords.first.nil?
      next if user_entry.passwords.first.start_with?('!', '*')

      describe "User #{user} password expiration" do
        subject { max_days.to_i }
        it { should cmp <= 365 }
        it { should cmp > 0 }
      end
    end
  end
end

control 'cis-5.4.1.2' do
  impact 1.0
  title 'Ensure minimum days between password changes is 1 or more'
  desc 'The PASS_MIN_DAYS parameter in /etc/login.defs allows an administrator to
        prevent users from changing their password until a minimum number of days
        have passed since the last password change.'
  desc 'rationale', 'By restricting the frequency of password changes, an
        administrator can prevent users from repeatedly changing their password
        in an attempt to circumvent password reuse controls.'
  desc 'check', 'Verify PASS_MIN_DAYS is 1 or more in /etc/login.defs and for
        all users in /etc/shadow.'

  tag cis: '5.4.1.2'
  tag level: 1

  ref 'CIS Benchmark', url: 'https://www.cisecurity.org/cis-benchmarks'

  describe login_defs do
    its('PASS_MIN_DAYS') { should cmp >= 1 }
  end

  # Check all users with passwords
  shadow_file = '/etc/shadow'

  if file(shadow_file).exist?
    shadow(shadow_file).users.each do |user|
      user_entry = shadow(shadow_file).filter(user: user)
      min_days = user_entry.min_days.first

      # Skip users with no password or locked accounts
      next if user_entry.passwords.first.nil?
      next if user_entry.passwords.first.start_with?('!', '*')

      describe "User #{user} minimum days between password changes" do
        subject { min_days.to_i }
        it { should cmp >= 1 }
      end
    end
  end
end

control 'cis-5.4.1.3' do
  impact 1.0
  title 'Ensure password expiration warning days is 7 or more'
  desc 'The PASS_WARN_AGE parameter in /etc/login.defs allows an administrator to
        notify users that their password will expire in a defined number of days.'
  desc 'rationale', 'Providing an advance warning that a password will be expiring
        gives users time to think of a secure password. Users caught unaware may
        choose a simple password or write it down where it may be discovered.'
  desc 'check', 'Verify PASS_WARN_AGE is 7 or more in /etc/login.defs and for
        all users in /etc/shadow.'

  tag cis: '5.4.1.3'
  tag level: 1

  ref 'CIS Benchmark', url: 'https://www.cisecurity.org/cis-benchmarks'

  describe login_defs do
    its('PASS_WARN_AGE') { should cmp >= 7 }
  end

  # Check all users with passwords
  shadow_file = '/etc/shadow'

  if file(shadow_file).exist?
    shadow(shadow_file).users.each do |user|
      user_entry = shadow(shadow_file).filter(user: user)
      warn_days = user_entry.warn_days.first

      # Skip users with no password or locked accounts
      next if user_entry.passwords.first.nil?
      next if user_entry.passwords.first.start_with?('!', '*')

      describe "User #{user} password warning days" do
        subject { warn_days.to_i }
        it { should cmp >= 7 }
      end
    end
  end
end

control 'cis-5.4.1.4' do
  impact 1.0
  title 'Ensure inactive password lock is 30 days or less'
  desc 'User accounts that have been inactive for over a given period of time can
        be automatically disabled. It is recommended that accounts that are inactive
        for 30 days after password expiration be disabled.'
  desc 'rationale', 'Inactive accounts pose a threat to system security since the
        users are not logging in to notice failed login attempts or other anomalies.'
  desc 'check', 'Verify INACTIVE is set to 30 or less in /etc/default/useradd and
        for all users in /etc/shadow.'

  tag cis: '5.4.1.4'
  tag level: 1

  ref 'CIS Benchmark', url: 'https://www.cisecurity.org/cis-benchmarks'

  # Check default useradd configuration
  useradd_defaults = '/etc/default/useradd'

  if file(useradd_defaults).exist?
    describe parse_config_file(useradd_defaults) do
      its('INACTIVE') { should cmp <= 30 }
      its('INACTIVE') { should cmp >= 0 }
    end
  end

  # Check all users with passwords
  shadow_file = '/etc/shadow'

  if file(shadow_file).exist?
    shadow(shadow_file).users.each do |user|
      user_entry = shadow(shadow_file).filter(user: user)
      inactive_days = user_entry.inactive_days.first

      # Skip users with no password or locked accounts
      next if user_entry.passwords.first.nil?
      next if user_entry.passwords.first.start_with?('!', '*')
      # Skip if inactive is not set (empty string)
      next if inactive_days.nil? || inactive_days.to_s.empty?

      describe "User #{user} inactive password lock" do
        subject { inactive_days.to_i }
        it { should cmp <= 30 }
        it { should cmp >= 0 }
      end
    end
  end
end

control 'cis-5.4.1.5' do
  impact 1.0
  title 'Ensure all users last password change date is in the past'
  desc 'All users should have a password change date in the past.'
  desc 'rationale', 'If a user recorded password change date is in the future then
        they could bypass any set password expiration.'
  desc 'check', 'Verify all users have a password change date in the past.'

  tag cis: '5.4.1.5'
  tag level: 1

  ref 'CIS Benchmark', url: 'https://www.cisecurity.org/cis-benchmarks'

  shadow_file = '/etc/shadow'
  today = (Time.now.to_i / 86_400).floor

  if file(shadow_file).exist?
    shadow(shadow_file).users.each do |user|
      user_entry = shadow(shadow_file).filter(user: user)
      last_change = user_entry.last_changes.first

      # Skip users with no password or locked accounts
      next if user_entry.passwords.first.nil?
      next if user_entry.passwords.first.start_with?('!', '*')
      # Skip if last_change is not set
      next if last_change.nil? || last_change.to_s.empty?

      describe "User #{user} last password change date" do
        subject { last_change.to_i }
        it 'should be in the past' do
          expect(subject).to be <= today
        end
      end
    end
  end
end

# ------------------------------------------------------------------------------
# Section 5.4.2 - 5.4.5 - User Accounts and Environment
# ------------------------------------------------------------------------------

control 'cis-5.4.2' do
  impact 1.0
  title 'Ensure system accounts are secured'
  desc 'There are a number of accounts provided with most distributions that are
        used to manage applications and are not intended to provide an interactive
        shell.'
  desc 'rationale', 'It is important to make sure that accounts that are not being
        used by regular users are prevented from being used to provide an
        interactive shell. By default, most distributions set the password field
        for these accounts to an invalid string, but it is also recommended that
        the shell field be set to /sbin/nologin or /usr/sbin/nologin.'
  desc 'check', 'Verify system accounts have nologin shell and are locked.'

  tag cis: '5.4.2'
  tag level: 1

  ref 'CIS Benchmark', url: 'https://www.cisecurity.org/cis-benchmarks'

  # Define system account UID threshold (typically 1000)
  min_uid = login_defs.UID_MIN.to_i || 1000

  # Valid nologin shells
  nologin_shells = %w[
    /sbin/nologin
    /usr/sbin/nologin
    /bin/false
    /usr/bin/false
  ]

  # Accounts that should be excluded from this check
  excluded_accounts = %w[root sync shutdown halt]

  passwd('/etc/passwd').uids.each_with_index do |uid, index|
    user = passwd('/etc/passwd').users[index]
    shell = passwd('/etc/passwd').shells[index]

    # Only check system accounts (UID < min_uid) that are not excluded
    next unless uid.to_i < min_uid
    next if excluded_accounts.include?(user)

    describe "System account #{user} shell" do
      subject { shell }
      it 'should be a nologin shell' do
        expect(nologin_shells).to include(subject)
      end
    end

    # Check that password is locked (starts with ! or *)
    user_shadow = shadow('/etc/shadow').filter(user: user)
    next if user_shadow.passwords.first.nil?

    describe "System account #{user} password" do
      subject { user_shadow.passwords.first }
      it 'should be locked' do
        expect(subject).to match(/^[!*]/)
      end
    end
  end
end

control 'cis-5.4.3' do
  impact 1.0
  title 'Ensure default group for the root account is GID 0'
  desc 'The usermod command can be used to specify which group the root user
        belongs to. This affects permissions of files that are created by the
        root user.'
  desc 'rationale', 'Using GID 0 for the root account helps prevent root-owned
        files from accidentally becoming accessible to non-privileged users.'
  desc 'check', 'Verify root user default group is GID 0.'

  tag cis: '5.4.3'
  tag level: 1

  ref 'CIS Benchmark', url: 'https://www.cisecurity.org/cis-benchmarks'

  describe passwd.where(user: 'root') do
    its('gids') { should cmp 0 }
  end

  describe user('root') do
    its('gid') { should eq 0 }
  end
end

control 'cis-5.4.4' do
  impact 1.0
  title 'Ensure default user umask is 027 or more restrictive'
  desc 'The user file-creation mode mask (umask) is used to determine the file
        permission for newly created directories and files. In Linux, the default
        permissions for any newly created directory is 0777 (rwxrwxrwx), and for
        any newly created file it is 0666 (rw-rw-rw-). The umask value subtracts
        permissions from these defaults.'
  desc 'rationale', 'Setting a restrictive umask ensures that newly created files
        and directories are not accessible to "other" users and limits access to
        the group owner.'
  desc 'check', 'Verify the default umask is 027 or more restrictive in profile files.'

  tag cis: '5.4.4'
  tag level: 1

  ref 'CIS Benchmark', url: 'https://www.cisecurity.org/cis-benchmarks'

  # Define the profile files to check
  profile_files = %w[
    /etc/profile
    /etc/bashrc
    /etc/bash.bashrc
    /etc/profile.d/*.sh
  ]

  # Check /etc/login.defs UMASK
  describe login_defs do
    its('UMASK') { should cmp '027' }
  end

  # Acceptable umask values (027 or more restrictive)
  # 027 = rwxr-x--- (no access for others)
  # 077 = rwx------ (no access for group or others)
  acceptable_umasks = %w[027 077 0027 0077 u=rwx,g=rx,o=]

  umask_found = false

  # Check /etc/profile
  profile_file = '/etc/profile'
  if file(profile_file).exist?
    describe file(profile_file) do
      its('content') { should match(/^\s*umask\s+[0-7]+/) }
    end

    content = file(profile_file).content
    umask_match = content.match(/^\s*umask\s+([0-7]+)/)
    if umask_match
      umask_found = true
      umask_value = umask_match[1]

      describe "#{profile_file} umask value" do
        subject { umask_value.to_i(8) }
        it 'should be 027 or more restrictive' do
          # 027 in octal = 23 in decimal
          # More restrictive means higher value (077 = 63)
          expect(subject).to be >= 23
        end
      end
    end
  end

  # Check /etc/bashrc
  bashrc_file = '/etc/bashrc'
  if file(bashrc_file).exist?
    content = file(bashrc_file).content
    umask_match = content.match(/^\s*umask\s+([0-7]+)/)
    if umask_match
      umask_found = true
      umask_value = umask_match[1]

      describe "#{bashrc_file} umask value" do
        subject { umask_value.to_i(8) }
        it 'should be 027 or more restrictive' do
          expect(subject).to be >= 23
        end
      end
    end
  end

  # Check /etc/bash.bashrc (Debian/Ubuntu)
  bash_bashrc_file = '/etc/bash.bashrc'
  if file(bash_bashrc_file).exist?
    content = file(bash_bashrc_file).content
    umask_match = content.match(/^\s*umask\s+([0-7]+)/)
    if umask_match
      umask_found = true
      umask_value = umask_match[1]

      describe "#{bash_bashrc_file} umask value" do
        subject { umask_value.to_i(8) }
        it 'should be 027 or more restrictive' do
          expect(subject).to be >= 23
        end
      end
    end
  end

  describe 'Umask should be configured in profile files' do
    subject { umask_found }
    it { should be true }
  end
end

control 'cis-5.4.5' do
  impact 1.0
  title 'Ensure default user shell timeout is 900 seconds or less'
  desc 'TMOUT is an environmental setting that determines the timeout of a shell
        in seconds. If TMOUT is not set, or set to 0, a shell will not timeout.'
  desc 'rationale', 'Setting a timeout value reduces the risk of unauthorized
        users accessing another user''s shell session while it is left unattended.'
  desc 'check', 'Verify TMOUT is set to 900 seconds or less in profile files and
        is readonly.'

  tag cis: '5.4.5'
  tag level: 1

  ref 'CIS Benchmark', url: 'https://www.cisecurity.org/cis-benchmarks'

  # Define the profile files to check
  profile_files = %w[
    /etc/profile
    /etc/bashrc
    /etc/bash.bashrc
  ]

  tmout_found = false
  tmout_readonly = false

  profile_files.each do |profile_file|
    next unless file(profile_file).exist?

    content = file(profile_file).content

    # Check for TMOUT setting
    tmout_match = content.match(/^\s*(?:export\s+)?TMOUT=(\d+)/)
    next unless tmout_match

    tmout_found = true
    tmout_value = tmout_match[1].to_i

    describe "#{profile_file} TMOUT value" do
      subject { tmout_value }
      it { should cmp <= 900 }
      it { should cmp > 0 }
    end

    # Check if TMOUT is set as readonly
    if content.match?(/^\s*readonly\s+TMOUT/) || content.match?(/^\s*declare\s+-r\s+TMOUT/)
      tmout_readonly = true
    end

    # Check if TMOUT is exported
    describe "#{profile_file} TMOUT export" do
      subject { content }
      it 'should export TMOUT' do
        expect(subject).to match(/export\s+TMOUT|^\s*TMOUT=.*;\s*export\s+TMOUT/)
      end
    end
  end

  # Also check /etc/profile.d/ for tmout configuration
  Dir.glob('/etc/profile.d/*.sh').each do |profile_d_file|
    next unless file(profile_d_file).exist?

    content = file(profile_d_file).content

    tmout_match = content.match(/^\s*(?:export\s+)?TMOUT=(\d+)/)
    next unless tmout_match

    tmout_found = true
    tmout_value = tmout_match[1].to_i

    describe "#{profile_d_file} TMOUT value" do
      subject { tmout_value }
      it { should cmp <= 900 }
      it { should cmp > 0 }
    end

    if content.match?(/^\s*readonly\s+TMOUT/) || content.match?(/^\s*declare\s+-r\s+TMOUT/)
      tmout_readonly = true
    end
  end

  describe 'TMOUT should be configured' do
    subject { tmout_found }
    it { should be true }
  end

  describe 'TMOUT should be readonly' do
    subject { tmout_readonly }
    it { should be true }
  end
end
