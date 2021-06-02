# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_17
class compliance::windows::item::w_17 (
  Boolean $report_only = true,
  String $policy_value1 = '0xFF',
  String $policy_value2 = '0xFF',
){
# The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_18'
  $item_title1   = 'Disable Autorun on drives'
  $setting_desc1 = 'Disable Autorun on CD drives'
  $item_title2   = 'Disable Autorun on drives'
  $setting_desc2 = 'Disable Autorun on CD drives'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  registry_value { compliance::policy_title($item_id,$item_title1,$setting_desc1,$policy_value1) :
    ensure => present,
    path   => 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CDROM\\AutoRun',
    type   => 'dword',
    data   => $policy_value1,
  }
  registry_value { compliance::policy_title($item_id,$item_title2,$setting_desc2,$policy_value2) :
    ensure => present,
    path   => 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun',
    type   => 'dword',
    data   => $policy_value2,
  }
}
