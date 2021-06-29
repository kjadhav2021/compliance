# compliance::windows::item::w_7
#
# **Title:** Disable the Guest account
#
# **Description:** A default Windows Server 2016 installation creates a guest account.
#
# **Impact:** The guest account may allow unauthorized access.
#
# **Risk Rating:** Medium
#
# **Standard Setting:** Disable the guest account from computer management.
#                       Click Start > Run and type compmgmt.msc
#                       Expand Local User & Groups > Users container
#                       Disable the Guest account
#
# @param report_only Whether or not to set the resources to noop mode
# @param policy_value 0 or 1 to disable or enable local security policy respectively
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
