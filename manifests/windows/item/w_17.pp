# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_17
class compliance::windows::item::w_17 {
  registry_value { 'HKEY_LOCAL_MACHINE\ SYSTEM\CurrentControlSet\Services\CDROM\AutoRun':
    ensure => present,
    type   => dword,
    data   => 0xFF,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun':
    ensure => present,
    type   => dword,
    data   => 0xFF,
  }
}
