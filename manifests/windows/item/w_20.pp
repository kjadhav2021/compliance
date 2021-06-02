# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_20
class compliance::windows::item::w_20 (
  Boolean $report_only = true,
  String $policy_value1 = '0x00000001',
  String $policy_value2 = '0x00000000'
){
# The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_20'
  $item_title   = 'Disable/Lockdown USB devices'
  $setting_desc1 = 'Disable/Lockdown USB devices-all users'
  $setting_desc2 = 'Disable/Lockdown USB devices-admin users'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  registry_value { compliance::policy_title($item_id,$item_title,$setting_desc1,$policy_value1) :
    ensure => present,
    path   => 'HKLM\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions\\DenyRemovableDevices',
    type   => 'dword',
    data   => $policy_value1,
  }
  registry_value { compliance::policy_title($item_id,$item_title,$setting_desc2,$policy_value2) :
    ensure => present,
    path   => 'HKLM\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions\\AllowAdminInstall',
    type   => 'dword',
    data   => $policy_value2,
  }
}
