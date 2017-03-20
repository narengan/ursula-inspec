control 'SWIFT001' do
  impact 0.1
  title 'Strict ownership and permissions for Swift log files to prevent unauthorized users from accessing them.'
  desc 'Strict ownership(swift user and group ) and permissions(640) for swift configuration files to prevent unauthorized users from accessing them.'
  tag 'production','development'
  tag 'swift'
  tag remediation: 'ursula <env> site.yml --tags=swift'
  files = ['account-server.conf', 'container-server.conf', 'dispersion.conf', 'drive-audit.conf', 'object-expirer.conf', 'object-server.conf', 'proxy-server.conf', 'swift.conf']
  files.each do |file|
    if File.file?("/etc/swift/#{file}")
      describe file("/etc/swift/#{file}") do
        its ('group') { should eq 'swift' }
        its ('owner') { should eq 'swift' }
        its ('mode') { should cmp 640 }
      end
    end
  end
end

control 'SWIFT002' do
  impact 0.1
  title 'Strict ownership and permissions for Swift configuration directory to prevent unauthorized users from accessing them.'
  desc 'Strict ownership(swiftops user and group ) and permissions(755) for swift configuration folder to prevent unauthorized users from accessing them.'
  tag 'production','development'
  tag 'swift'
  tag remediation: 'ursula <env> site.yml --tags=swift'
  describe file('/etc/swift/') do
    its ('group') { should eq 'swiftops' }
    its ('owner') { should eq 'swiftops' }
    its ('mode') { should cmp 755 }
  end
end

control 'SWIFT003' do
  impact 0.1
  title 'Strict ownership and permissions for Swift log files to prevent unauthorized users from accessing them.'
  desc 'Strict ownership(syslog user and adm group ) and permissions(640) for swift log files to prevent unauthorized users from accessing them.For audit purposes, the log file should not be editable by anyone other than the process that is writing to that file.'
  tag 'production','development'
  tag 'swift'
  tag remediation: 'ursula <env> site.yml --tags=swift'
  files = ['account.log', 'container.log', 'object.log', 'proxy.log']
  files.each do |file|
    if File.file?("/var/log/swift/#{file}")
      describe file("/var/log/swift/#{file}") do
        its ('owner') { should eq 'syslog' }
        its ('group') { should eq 'adm' }
        its ('mode') { should cmp 640 }
      end
    end
  end
end

control 'SWIFT004' do
  impact 0.1
  title 'Swift logging level must be set to info'
  desc 'Swift logging level must be set to info to get errors, warnings and informational messages'
  tag 'production','development'
  tag 'swift'
  tag remediation: 'ursula <env> site.yml --tags=swift'
  files = ['account.log', 'container.log', 'object.log', 'proxy.log']
  files = ['object-expirer.conf', 'drive-audit.conf', 'container-server.conf', 'proxy-server.conf', 'account-server.conf', 'object-server.conf']
  files.each do |file|
    if File.file?("/etc/swift/#{file}")
      describe file("/etc/swift/#{file}") do
        it { should contain '^log_level = INFO' }
      end
    end
  end
end
