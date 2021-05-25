# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_18
class compliance::windows::item::w_18 {
  registry_value { 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters\NoNameReleaseOnDemand':
    ensure => present,
    type   => dword,
    data   => 0x00000001,
  }
}
