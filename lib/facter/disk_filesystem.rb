# This fact is used to return a list of local SIDS so we can correctly
# process CIS 19.x rules.  These rules must be set for each USER/SID
# present inside HKEY_USER
Facter.add(:filesystem) do
  confine kernel: 'windows'
  setcode do
    fs_list = []
    powershell = 'C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe'
    command = '[system.io.driveinfo]::GetDrives() | format-table -property Name,Driveformat'
    value = Facter::Util::Resolution.exec(%(#{powershell} -command "#{command}"))
    value.split.each do |line|
      # if line =~ %r{S\-1\-5\-.*\d$}
        fs_list << line.gsub(" ","-")
      # end
    end
    fs_list
  end
end
