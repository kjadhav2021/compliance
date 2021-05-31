# This fact is used to return a list of drives with filesystem type
Facter.add(:filesystem) do
  confine kernel: 'windows'
  setcode do
    filesystem_list = []
    powershell = 'C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe'
    command = '[system.io.driveinfo]::GetDrives() | format-table -property Name,Driveformat -hidetableheaders'
    value = Facter::Util::Resolution.exec(%(#{powershell} -command "#{command}"))
    value.split('/\n+/').each do |line|
      filesystem_list << line.split(' ')[0] + '*' + line.split(' ')[1]
    end
    filesystem_list
  end
end
