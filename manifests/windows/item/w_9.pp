# compliance::windows::item::w_9
#
# **Title:** Enforce a strong password and account policy
#
# **Description:** Password policies help administrators enforce the strength of passwords that users can set.
#                  Password policy is required to control user password characteristics including password minimum
#                  length, maximum length and password aging.
#
# **Impact:** Brute forcing the weak passwords can result in unauthorized access.
#
# **Risk Rating:** High
#
# **Standard Setting:** Click Start > Run and type gpedit.msc
#                       Expand Computer Configuration > Windows Settings > Security Settings
#                       > Account Policy > Password Policy or Account Lockout Policy container
# **Note:** Note: These settings will be applied after a reboot. To apply the settings instantly,
#                 right click on Security Settings and select Reload.
#
# @param security_policies security policies that need to be enforced
# @param report_only Whether or not to set the resources to noop mode
class compliance::windows::item::w_9 (
  Hash $security_policies,
  Boolean $report_only = true,
){
# The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_9'
  $item_title   = 'Enforce a strong password and account policy'
  $setting_desc = 'Enforce a strong password and account policy'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  # Password policy
  # Local_security_policy {
  #   ensure => present,
  # }
  # create_resources(local_security_policy,$security_policies)
  $security_policies.each | $k,$d | {
    local_security_policy { $d['title']:
      ensure       => present,
      policy_value => $d['policy_value'],
    }
  }
}
