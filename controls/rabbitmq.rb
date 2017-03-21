control 'RABBITMQ001' do
  impact 1.0
  title 'Provide non-admin ID for RabbitMQ service'
  desc 'Check if there is a RabbitMQ user present and is part of the RabbitMQ group to prevent unauthorized access'
  tag 'production','development'
  tag 'rabbitmq'
  tag remediation: 'ursula <env> site.yml --tags=rabbitmq'
  ref ' https://www.rabbitmq.com/production-checklist.html'
  describe user('rabbitmq') do
      it { should exist }
      its('groups') { should include('rabbitmq') }
  end
end

control 'RABBITMQ002' do
  impact 1.0
  title 'RabbitMQ password requirements'
  desc 'RabbitMq password must be of length greater than or equal 8 characters to be secure'
  tag 'production','development'
  tag 'rabbitmq'
  tag remediation: 'ursula <env> site.yml --tags=rabbitmq'
  describe file('/etc/nova/nova.conf') do
    its('content') { should_not include('/(rabbit_password=\w{0,7})$/') }
  end
end

control 'RABBITMQ003' do
  impact 1.0
  title 'RabbitMQ proccess should be run by non root user'
  desc 'RabbitMQ process should be run by RabbitMQ user to avoid unauthorized access'
  tag 'production','development'
  tag 'rabbitmq'
  tag remediation: 'ursula <env> site.yml --tags=rabbitmq'
  describe processes("rabbitmq") do
    its('users') { should include 'rabbitmq' }
  end
end

control 'RABBITMQ004' do
  impact 0.5
  title 'Rabbitmq-env.conf configuration file must have secure permissions to avoid unauthorized access'
  desc 'the configuartion file of RabbitMQ should be set to permission 600 and owned by RabbitMQ user'
  tag 'production','development'
  tag 'rabbitmq'
  tag remediation: 'ursula <env> site.yml --tags=rabbitmq'
    describe file("/etc/rabbitmq/rabbitmq-env.conf") do
      it { should be_file }
      its('mode') { should cmp '0600' }
      its('owner') { should eq 'rabbitmq' }
      its('group') { should eq 'rabbitmq' }
    end
end

control 'RABBITMQ005' do
  impact 0.5
  title 'Strict ownership and permissions for RabbitMQ log files to prevent unauthorized users from accessing them.'
  desc 'Strict ownership(rabbitmq user and group ) and permissions(644) for rabbitmq log files to prevent unauthorized users from accessing them.For audit purposes, the log file should not be editable by anyone other than the process that is writing to that file.'
  tag 'production','development'
  tag 'rabbitmq'
  tag remediation: 'ursula <env> site.yml --tags=rabbitmq'
  hostname = `hostname -s`.strip
  files = ["rabbit@#{hostname}.log", "rabbit@#{hostname}-sasl.log", 'shutdown_err', 'shutdown_log', 'startup_err', 'startup_log']
  files.each do |file|
    if File.file?("/var/log/rabbitmq/#{file}")
      describe file("/var/log/rabbitmq/#{file}") do
        its('mode') { should cmp '0644' }
        its('owner') { should eq 'rabbitmq' }
        its('group') { should eq 'rabbitmq' }
      end
    end
  end
end

control 'RABBITMQ006' do
  impact 0.5
  title '"guest" user can only be used locally'
  desc 'RabbitMQ server will prevent default users to connect remotely, "guest" user must in  default user list'
  tag 'production','development'
  tag 'rabbitmq'
  tag remediation: 'ursula <env> site.yml --tags=rabbitmq'
  describe command('rabbitmqctl environment | grep default_user') do
    output = "      {default_user,<<\"guest\">>},\n      {default_user_tags,[administrator]},\n"
    its(:stdout) { should eq output }
  end
 end

control 'RABBITMQ007' do
  impact 0.5
  title 'RabbitMQ logging level must be set to info'
  desc 'RabbitMQ logging level must be set to info to get errors, warnings and informational messages'
  tag 'production','development'
  tag 'rabbitmq'
  tag remediation: 'ursula <env> site.yml --tags=rabbitmq'
  describe command('rabbitmqctl environment | grep log_level | tr -d " ""\n"') do
    output = "{log_levels,[{connection,info}]},"
    its(:stdout){ should match (output) }
  end
end
