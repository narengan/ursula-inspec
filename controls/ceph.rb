control 'CEPH001' do
  impact 1.0
  title 'Strict permissions for configuration files in /etc/ceph directory to prevent unauthorized users from accessing them.'
  desc 'Strict permissions(644) and ownership (root user and group) for configuration files in /etc/ceph directory to prevent unauthorized users from accessing them.'
  tag 'production','development'
  tag 'ceph'
  tag remediation: 'ursula <env> site.yml --tags=ceph'
  files = ['ceph.conf', 'cinder_uuid', 'fsid']
  files.each do |file|
    describe file("/etc/ceph/#{file}") do
      its('owner') { should eq 'root' }
      its('group') { should eq 'root' }
      its('mode') { should cmp '0644' }
    end
  end
end

control 'CEPH002' do
  impact 1.0
  title 'Strict permissions for /etc/ceph/rbdmap to prevent unauthorized users'
  desc 'Strict permissions(644) and ownership (root user and group) for /etc/ceph/rbdmap to prevent unauthorized users'
  tag 'production','development'
  tag 'ceph'
  tag remediation: 'ursula <env> site.yml --tags=ceph'
  describe file("/etc/ceph/rbdmap") do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0755' }
  end
end

control 'CEPH003' do
  impact 1.0
  title 'Strict permissions for /etc/ceph/rbdmap to prevent unauthorized users'
  desc 'Strict permissions(644) and ownership (root user and group) for /etc/ceph/rbdmap to prevent unauthorized users'
  tag 'production','development'
  tag 'ceph'
  tag remediation: 'ursula <env> site.yml --tags=ceph'
  files = Dir['/var/log/ceph/*.log']
  files.each do |file|
    if File.exist?("#{file}")
      describe file("#{file}") do
         # ceph.log is owned by ceph on cpm nodes
         # but it owned by root on osd nodes
        its('owner') { should match '^root$|^ceph$' }
        its('group') { should eq 'ceph' }
        its('mode') { should cmp '0644' }
      end
    end
  end
end
