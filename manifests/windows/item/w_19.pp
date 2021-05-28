# @summary
#
# Disable the DNS cache
#
# @example
#   include compliance::windows::item::w_19
class compliance::windows::item::w_19 {
  #disabling the DNS cache using registry
  compliance::windows::regedit_entry { 'disable the DNS cache':
    registry_key => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\DNScache\Parameters\SecureResponse',
    type         => 'dword',
    value        => '0x00000001',
  }
}
