# OS security facts
require 'facter'
require 'json'
require 'utils/win_helper'

# files_list_limit = 30

def cis_item_classfile
  File.read(Puppet['classfile']).split('\n').select { |f| f.include? '::item' }
end

os_security_facts = {}
if Facter.value(:kernel) == 'Linux'
  if File.file?(Puppet['classfile'])
    users_empty_passfield_cmd = "getent shadow | grep '^[^:]*:..\\?:' | cut -d: -f1"
    grub_cmdline_linux_cmd = "cat /etc/default/grub | grep ^GRUB_CMDLINE_LINUX | cut -d= -f2- | sed 's/\"//g'"
    swapon_cmd = 'cat /proc/swaps | tail -1'

    users_empty_passfield = Facter::Core::Execution.execute(users_empty_passfield_cmd).split(%r{\n+})
    grub_cmdline_linux = Facter::Core::Execution.execute(grub_cmdline_linux_cmd).split(' ') if File.exist? '/etc/default/grub'
    swapon = Facter::Core::Execution.execute(swapon_cmd).split(' ') if File.exist? '/proc/swaps'

    os_security_facts['users_empty_passfield'] = users_empty_passfield unless users_empty_passfield.empty?
    os_security_facts['grub_cmdline_linux'] = grub_cmdline_linux unless grub_cmdline_linux.nil?
    os_security_facts['swap'] = swapon unless swapon.nil?
  end
elsif Facter.value(:kernel) == 'windows'
  directories_acl = {}
  dir_acl_list = { 'windir' => ENV['windir'] }

  dir_acl_list.each do |k, d|
    acl_data = win_acl(file: d)
    directories_acl[k] = acl_data unless acl_data.nil?
  end

  os_security_facts['directories_acl'] = directories_acl unless directories_acl.empty?
end

Facter.add('os_security_facts') { setcode { os_security_facts } } unless os_security_facts.empty?
