# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_6
class compliance::windows::item::w_6 {
  compliance::windows::regedit_entry { 'Secure the SNMP service - readonly':
        registry_key => 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities\TEJAq0jPaNXOUlDSyBdp',
        type         => 'dword',
        value        => '0x00000004',
  }
}
