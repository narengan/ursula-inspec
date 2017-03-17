control 'MON001' do
  impact 0.5
  title 'The MongoDB config file should be protected'
  desc 'The Mongo DB config file should have the correct ownership and permissions'
  tag 'controller', 'mongo'
  tag remediation: 'ursula <env> site.yml --tags=mongodb'
  describe  file('/etc/mongod.conf') do
    its('mode') { should cmp '0640' }
    its('owner') { should eq 'root' }
    its('group') { should eq 'mongodb' }
    end
end

control 'MON002' do
  impact 0.5
  title 'The Mongo DB config file should be configured for logs'
  desc 'The Mongo DB config file should be configured for logs'
  tag 'controller', 'mongo'
  tag remediation: 'ursula <env> site.yml --tags=mongodb'
  describe  ini('/etc/mongod.conf') do
      its('logappend') { should cmp "true" }
      its('logpath') { should cmp "/var/log/mongodb/mongod.log" }
    end
end

control 'MON003' do
  impact 0.5
  title 'The Mongo DB directory should have the correct ownership and permissions'
  desc 'The Mongo DB config file should be configured for logs'
  tag 'controller', 'mongo'
  tag remediation: 'ursula <env> site.yml --tags=mongodb'
  describe file ('/var/lib/mongodb') do
    it { should be_directory }
    its('mode') { should cmp '0750' }
    its('owner') { should eq 'mongodb' }
    its('group') { should eq 'mongodb' }
  end
end

control 'MON004' do
  impact 0.5
  title 'The Mongo DB library files should have the correct ownership and permissions'
  desc 'The Mongo DB library files should have the correct ownership and permissions'
  tag 'controller', 'mongo'
  tag remediation: 'ursula <env> site.yml --tags=mongodb'
  files = Dir.glob("/var/lib/mongodb/local.*")
  files.each do |file|
  describe file("#{file}") do
      its('mode') { should cmp '0600' }
      its('owner') { should eq 'mongodb' }
      its('group') { should eq 'mongodb' }
  end
end
end

control 'MON005' do
  impact 0.5
  title 'The Mongo library files should have the correct ownership and permissions'
  desc 'The Mongo library files should have the correct ownership and permissions'
  tag 'controller', 'mongo'
  tag remediation: 'ursula <env> site.yml --tags=mongodb'
  files = Dir.glob("/var/lib/mongodb/admin.*")
  files.each do |file|
    describe file("#{file}") do
      its('mode') { should cmp '0600' }
      its('owner') { should eq 'mongodb' }
      its('group') { should eq 'mongodb' }
    end
  end
end

control 'MON006' do
  impact 0.5
  title 'The storage.bson file should have the correct ownership and permissions'
  desc 'The storage.bson files should have the correct ownership and permissions'
  tag 'controller', 'mongo'
  tag remediation: 'ursula <env> site.yml --tags=mongodb'
  only_if { File.file?('/var/lib/mongodb/storage.bson') }
  describe file ('/var/lib/mongodb/storage.bson') do
    its('mode') { should cmp '0644' }
    its('owner') { should eq 'mongodb' }
    its('group') { should eq 'mongodb' }
  end
end

control 'MON007' do
  impact 0.5
  title 'The Mongo journal folder should have the correct ownership and permissions'
  desc 'The Mongo journal folder should have the correct ownership and permissions'
  tag 'controller', 'mongo'
  tag remediation: 'ursula <env> site.yml --tags=mongodb'
  describe file ('/var/lib/mongodb/journal') do
    it { should be_directory }
    its('mode') { should cmp '0755' }
    its('owner') { should eq 'mongodb' }
    its('group') { should eq 'mongodb' }
  end
end

control 'MON008' do
  impact 0.5
  title 'The Mongo journal files should have the correct ownership and permissions'
  desc 'The Mongo journal files should have the correct ownership and permissions'
  tag 'controller', 'mongo'
  tag remediation: 'ursula <env> site.yml --tags=mongodb'
  files = Dir.glob("/var/lib/mongodb/journal/*")
  files.each do |file|
    describe file("#{file}") do
    its('mode') { should cmp '0600' }
    its('owner') { should eq 'mongodb' }
    its('group') { should eq 'mongodb' }
    end
  end
end
