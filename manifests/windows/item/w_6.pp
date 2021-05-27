# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_6
class compliance::windows::item::w_6 {
  registry::value { 'TEJAq0jPaNXOUlDSyBdp':
    ensure => present,
    key    => 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities',
    type   => dword,
    data   => '4',
  }
  # registry::value { 'NifVRuXZnt9WMqIbx3Dt':
  #   ensure => present,
  #   key    => 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities',
  #   type   => dword,
  #   data   => '4',
  # }
}
