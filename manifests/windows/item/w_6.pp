# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_6
class compliance::windows::item::w_6 {
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities\TEJAq0jPaNXOUlDSyBdp':
    ensure => present,
    type   => dword,
    data   => 0x00000004,
  }
  # registry::value { 'NifVRuXZnt9WMqIbx3Dt':
  #   ensure => present,
  #   key    => 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities',
  #   type   => dword,
  #   data   => '4',
  # }
}
