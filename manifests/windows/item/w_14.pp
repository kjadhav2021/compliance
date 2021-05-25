# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_14
class compliance::windows::item::w_14 {
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel':
    ensure => present,
    type   => dword,
    data   => 90,
  }
}
