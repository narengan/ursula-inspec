max_days = attribute('pass_max_days', default: '90', description: 'Key name for the pass_max_days in login.defs')
control 'COMMON001' do
  impact 0.5
  title 'Passwords for new users must be restricted to a maximum lifetime.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  tag 'common', 'PASS-MAX-DAYS'
  tag remediation: 'Add or modify the following line in /etc/login.defs :
   PASS_MAX_DAYS     90'

  options = {
    assignment_regex: /^(\w+)\s+(\w+?)$/
  }
  describe parse_config_file('/etc/login.defs', options) do
    its('PASS_MAX_DAYS') { should_not eq nil }
    its('PASS_MAX_DAYS') { should be <= "#{max_days}" }
  end
end
