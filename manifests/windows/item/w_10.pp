# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_10
class compliance::windows::item::w_10 (
  Boolean $report_only = true,
){
# The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_10'
  $item_title   = 'Disable Guest user'
  $setting_desc = 'Disable Guest user'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
    exec { compliance::policy_title($item_id,$item_title,$setting_desc) :
    command  => 'Get-LocalUser Guest | Disable-LocalUser',
    provider => powershell,
  }
}
