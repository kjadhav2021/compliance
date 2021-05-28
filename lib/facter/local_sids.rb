# This fact is used to return a list of local SIDS
Facter.add(:cis_local_sids) do
  confine kernel: 'windows'
  setcode do
    sid_list = []
    powershell = 'C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe'
    command = '(Get-ChildItem "REGISTRY::HKEY_USERS").name'
    value = Facter::Util::Resolution.exec(%(#{powershell} -command "#{command}"))
    value.split.each do |line|
      if line =~ %r{S\-1\-5\-.*\d$}
        sid_list << line.split('\\')[1]
      end
    end
    sid_list
  end
end
