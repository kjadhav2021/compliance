# @summary
# 14.Allocate adequate space for the for Event viewer logs
#
# @example
#   include compliance::windows::item::w_14
class compliance::windows::item::w_14 {
  compliance::windows::regedit_entry { 'allocate adequate space for the for Event viewer logs':
    registry_key => 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel',
    type         => 'dword',
    value        => '90',
  }
}
