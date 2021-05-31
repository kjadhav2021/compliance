# This fact is used to return a list of drives with filesystem type
Facter.add(:filesystem) do
  confine kernel: 'windows'
  setcode do
    powershell = 'C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe'
    command = '[system.io.driveinfo]::GetDrives() | format-table -property Name,Driveformat -hidetableheaders'
    value = Facter::Util::Resolution.exec(%(#{powershell} -command "#{command}"))
    fs_list = value.split('/\n/')
    fs_list
  end
end
