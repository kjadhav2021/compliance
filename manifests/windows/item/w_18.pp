# @summary
# 18.Configure the system not to respond to name release command
#
#
# @example
#   include compliance::windows::item::w_18
class compliance::windows::item::w_18 {
  compliance::windows::regedit_entry { 'configure the system not to respond to name release command':
    registry_key => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters\NoNameReleaseOnDemand',
    type         => 'dword',
    value        => '0x00000001',
  }
}
