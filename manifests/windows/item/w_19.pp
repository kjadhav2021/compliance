# @summary
#
# Disable the DNS cache
#
# @example
#   include compliance::windows::item::w_19
class compliance::windows::item::w_19 (
  Boolean $report_only = true,
  String $policy_value = '0x00000001',
){
# The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_19'
  $item_title   = 'Disable the DNS cache'
  $setting_desc = 'Disable the DNS cache'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  registry_value { compliance::policy_title($item_id,$item_title,$setting_desc,$policy_value) :
    ensure => present,
    path   => 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\DNScache\\Parameters\\SecureResponse',
    type   => 'dword',
    data   => $policy_value,
  }
}
