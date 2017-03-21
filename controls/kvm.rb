control 'KVM001' do
  impact 1.0
  title 'KVM images should have the correct modes'
  desc 'Permissions must be 0640 or more restrictive on image files.'
  tag 'controller', 'nova'
  tag remediation: 'ursula <env> site.yml --tags=nova'
  files = Dir.glob("/var/lib/libvirt/images/*")
  files.each do |file|
    describe file("#{file}") do
    its('mode') { should cmp '0640' }
    end
  end
end

control 'KVM002' do
  impact 1.0
  title '/dev/kvm should have the correct mode'
  desc 'Permission on /dev/kvm must be 660 or more restrictive, if this file exists. /dev/kvm must be owned by root and be in the kvm group'
  tag 'controller', 'nova'
  tag remediation: 'ursula <env> site.yml --tags=nova'
  describe file('/dev/kvm') do
    it { should exist }
    its('mode') { should cmp '0660' }
    its('group') { should eq 'kvm' }
  end
end

control 'KVM003' do
  impact 1.0
  title 'libvirt should be configured correctly'
  desc ' Disable listen_tcp.'
  tag 'controller', 'nova'
  tag remediation: 'ursula <env> site.yml --tags=nova'
  describe ini('/etc/libvirt/libvirtd.conf') do
    its('unix_sock_group') { should match /^['"]libvirt['"]$/ }
    its('unix_sock_ro_perms') { should match /^['"]0770['"]$/ }
    its('unix_sock_rw_perms') { should match /^['"]0770['"]$/ }
    # The defaults should be fine
    its('listen_tcp') { should be_nil.or cmp "0" }
  end
end

control 'KVM004' do
  impact 1.0
  title 'qemu should be configured correctly'
  desc 'VNC must not listen on a public interface. Virtual machines must not run as root process'
  tag 'controller', 'nova'
  tag remediation: 'ursula <env> site.yml --tags=nova'
  describe ini('/etc/libvirt/qemu.conf') do
      its('user') { should match /^['"]qemu['"]$/ }
      its('group') { should match /^['"]qemu['"]$/ }
      # The defaults should be fine
      its('vnc_listen') { should be_nil.or match /^['"]127.0.0.1['"]$/ }
      its('dynamic_ownership') { should be_nil.or cmp "1" }
  end
end
