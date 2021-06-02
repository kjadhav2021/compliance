# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_7
class compliance::windows::item::w_7 (
  Boolean $report_only = true,
  String $policy_value = '0',
){

  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_7'
  $item_title   = 'Disable the Guest account'
  $setting_desc = 'Disable the guest account from computer management'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------

  local_security_policy { compliance::policy_title( $item_id, $item_title, $setting_desc, $policy_value):
    ensure       => present,
    name         => 'EnableGuestAccount',
    policy_value => $policy_value,
  }
}
