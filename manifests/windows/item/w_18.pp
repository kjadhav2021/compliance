# @summary
# 18.Configure the system not to respond to name release command
#
#
# @example
#   include compliance::windows::item::w_18
class compliance::windows::item::w_18 (
  Boolean $report_only = true,
  String $policy_value = '0x00000001',
){
# The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_18'
  $item_title   = 'Configure the system not to respond to name release command'
  $setting_desc = 'Configure the system not to respond to name release command'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  registry_value { compliance::policy_title($item_id,$item_title,$setting_desc,$policy_value) :
    ensure => present,
    path   => 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NetBT\\Parameters\\NoNameReleaseOnDemand',
    type   => 'dword',
    data   => $policy_value,
  }
}
