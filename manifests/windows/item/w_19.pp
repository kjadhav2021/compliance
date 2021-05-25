# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_19
class compliance::windows::item::w_19 {
  #disabling the DNS cache using registry
  registry_value { 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\DNScache\Parameters\SecureResponse':
    ensure => present,
    type   => dword,
    data   => 0x00000001,
  }
}
