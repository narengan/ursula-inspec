control 'MYSQL001' do
  impact 0.5
  title 'Does a mysql user exist?'
  desc 'Check if mysql user exists since the mysql process should be run my a not-root user'
  tag 'production','development'
  tag 'mysql'
  tag remediation: 'ursula <env> site.yml --tags=mysql'
  ref 'https://dev.mysql.com/doc/refman/5.7/en/security-guidelines.html'
  describe user('mysql') do
    it { should exist }
  end
end

control 'MYSQL002' do
  impact 0.5
  title 'Check mysql process runs as non root user'
  desc 'Mysqld process should be run my a non-root user.'
  tag 'production','development'
  tag 'mysql'
  tag remediation: 'ursula <env> site.yml --tags=mysql'
  ref 'https://dev.mysql.com/doc/mysql-security-excerpt/5.7/en/security-against-attack.html'
  describe mysql_conf.params('mysqld') do
      its('user') { should eq('mysql') }
  end
end

control 'MYSQL003' do
  impact 0.5
  title 'Mysql service directories should have permissions and ownership that prevent unauthorized users from accessing them.'
  desc 'Mysql service run directories must have secure permissions and strict ownership to prevent unauthorized users from accessing them.'
  tag 'production','development'
  tag 'mysql'
  tag remediation: 'ursula <env> site.yml --tags=mysql'
  files = {'/var/run/mysqld' => {'mode' => '0755','owner' => 'mysql', 'group' => 'mysql'},
           '/etc/mysql/' => {'mode' => '0755', 'owner' => 'root', 'group' => 'root' }}
  files.each do |file, meta|
    describe file("#{file}") do
      its('mode') { should cmp meta['mode']}
      its('group') { should eq meta['owner']}
      its('owner') { should eq meta['group']}
    end
  end
end

control 'MYSQL004' do
  impact 1.0
  title 'Strict permissions for configuration files in conf.d directory to prevent unauthorized users from accessing them.'
  desc 'Strict permissions(644) and ownership (root user and group) for configuration files in conf.d directory to prevent unauthorized users from accessing them.'
  tag 'production','development'
  tag 'mysql'
  tag remediation: 'ursula <env> site.yml --tags=mysql'
  files = ['bind-inaddr-any.cnf', 'replication.cnf', 'tuning.cnf' , 'utf8.cnf']
  files.each do |file|
    describe file("/etc/mysql/conf.d/#{file}") do
      its('mode') { should cmp '0644' }
      its('group') { should eq 'root' }
      its('owner') { should eq 'root'}
    end
  end
end

control 'MYSQL005' do
  impact 1.0
  title 'Strict permissions for my.cnf to prevent unauthorized users from accessing them.'
  desc 'strict permissions(644) and ownership (root user and group) for my.cnf to prevent unauthorized users from accessing them.'
  tag 'production','development'
  tag 'mysql'
  tag remediation: 'ursula <env> site.yml --tags=mysql'
  describe file("/etc/my.cnf") do
    its('mode') { should cmp '0644' }
    its('group') { should eq 'root' }
    its('owner') { should eq 'root'}
  end
end

control 'MYSQL006' do
  impact 1.0
  title 'The system must prevent modification of the system log files.'
  desc 'Strict ownership(mysql user and group ) and permissions(640) for mysql log files to prevent modifications of the log files. For audit purposes, the log file should not be editable by anyone other than the process that is writing to that file. '
  tag 'production','development'
  tag 'mysql'
  tag remediation: 'ursula <env> site.yml --tags=mysql'
  files = ['mysql.err', 'mysql.log' ]
  files.each do |file|
    if File.file?(file)
      describe file("/var/log/mysql/#{file}") do
        its('mode') { should cmp '0640' }
        its('group') { should eq 'mysql' }
        its('owner') { should eq 'mysql'}
       end
    end
  end
end
