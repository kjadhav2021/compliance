require 'facter'
require 'json'
require 'open3'
require 'utils/win_helper'
require 'win32/service'

powershellcmd = "#{ENV['windir']}/system32/WindowsPowershell/v1.0/powershell.exe "

if Facter.value(:kernel) == 'windows'
  raw_os_drive = Facter::Core::Execution.execute(powershellcmd + '"Get-WmiObject -Class Win32_Logicaldisk | Select-Object -Property DeviceID, DriveType, FreeSpace, Size, VolumeName, FileSystem | ConvertTo-Json"') # rubocop:disable Metrics/LineLength

  if %r{2008}.match?(Facter.value(:operatingsystemrelease))
    os_partition = {}
  else
    raw_os_partition = Facter::Core::Execution.execute(powershellcmd + '"Get-Disk | Select-Object -Property Number, SerialNumber, FriendlyName, OperationalStatus, size, PartitionStyle, isBoot, isSystem, isReadOnly, isOffline, isClustered, HealthStatus | ConvertTo-Json"') # rubocop:disable Metrics/LineLength
    os_partition_item = raw_os_partition.empty? ? [] : JSON.parse(raw_os_partition)
    os_partition = os_partition_item.is_a?(Hash) ? [os_partition_item] : os_partition_item
  end

  unless raw_os_drive.nil?
    os_drive = JSON.parse(raw_os_drive)
    drive = {}
    os_drive.each do |d|
      devid = d['DeviceID']
      drive[devid] = { 'type' => get_drive_type(d['DriveType']) }
      drive[devid]['freespace']     = d['FreeSpace']
      drive[devid]['size']          = d['Size']
      drive[devid]['volume_name']   = d['VolumeName']
      drive[devid]['filesystem']    = d['FileSystem']
      next unless d['FreeSpace'].to_i > 0
      drive[devid]['freespace_gb']    = d['FreeSpace'].to_i / 1_073_741_824
      drive[devid]['size_gb']         = d['Size'].to_i / 1_073_741_824
      drive[devid]['used_space']      = d['Size'].to_i - d['FreeSpace'].to_i
      drive[devid]['used_space_pct']  = (drive[devid]['used_space'].to_i / d['Size'].to_f * 100).ceil
    end
  end

  raw_shares = Facter::Core::Execution.execute(powershellcmd + '"get-WmiObject -Class Win32_Share | Select-Object -Property Name, Path, Description| ConvertTo-Json"')
  unless raw_shares.nil?
    shares_data = JSON.parse(raw_shares)
    shares = {}
    shares_data.each do |s|
      shares_permissions = {}
      name = s['Name']
      raw_shares_permissions = Facter::Core::Execution.execute(powershellcmd + '"Get-SmbShareAccess ' + name + ' | Select-Object -Property AccountName, AccessControlType, AccessRight| ConvertTo-Json"') # rubocop:disable Metrics/LineLength
      unless raw_shares_permissions.nil?
        shares_permissions_data = JSON.parse(raw_shares_permissions)
        shares_permissions_data = shares_permissions_data.is_a?(Hash) ? [shares_permissions_data] : shares_permissions_data
        shares_permissions_data.each do |sp|
          shares_permissions[sp['AccountName']] = { 'access_control_type' => get_shares_accesscontroltype(sp['AccessControlType']),
                                                    'access_right'        => get_shares_accessright(sp['AccessRight']) }
        end
      end
      shares[name] = { 'path' => s['Path'], 'description' => s['Description'], 'permissions' => shares_permissions }
    end
  end
end

Facter.add('windows_features') do
  confine osfamily: :windows
  setcode do
    Facter::Core::Execution.execute(powershellcmd + '"(Get-WindowsFeature | Where-Object {$_.Installed -match \"True\"} | Select-Object -expand Name) -join \",\""').split(',')
  end
end

Facter.add('windows_is_domain_controller') do
  confine osfamily: :windows
  setcode do
    # Facter::Core::Execution.execute('powershell (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain.ToString().ToLower()')
    Facter.value(:windows_features).include?('AD-Domain-Services')
  end
end

Facter.add('windows_ad_domain') do
  confine osfamily: :windows
  setcode do
    begin
      require 'win32ole'
      wmi = WIN32OLE.connect('winmgmts:\\\\.\\root\\cimv2')
      foo = wmi.ExecQuery('SELECT * FROM Win32_ComputerSystem').each.first
      foo.Domain
    rescue
      # do nothing but comment
      nil
    end
  end
end

Facter.add('windows_powershell') do
  confine osfamily: :windows
  powershell = {}
  setcode do
    powershell['major'] = Facter::Core::Execution.execute(powershellcmd + '$PSversiontable.psversion.major')
    powershell['minor'] = Facter::Core::Execution.execute(powershellcmd + '$PSversiontable.psversion.minor')
    powershell
  end
end

Facter.add('windows_firewall') do
  confine osfamily: :windows
  setcode do
    firewall_srv = 'MpsSvc'
    if ::Win32::Service.exists?(firewall_srv) && ::Win32::Service.status(firewall_srv)['current_state'] == 'running'
      Puppet::Resource.indirection.search('windowsfirewall').map { |f|
        YAML.safe_load(f.to_hierayaml)
      }.reduce({}, :merge)
    end
  end
end

Facter.add('partition') { setcode { os_partition } } unless os_partition.nil?
Facter.add('drive') { setcode { drive } } unless drive.nil?
Facter.add('windows_shares') { setcode { shares } } unless shares.nil?
