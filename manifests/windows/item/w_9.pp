# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_9
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
    local_security_policy { $d['Name']:
      ensure       => present,
      policy_value => $d['policy_value'],
    }
  }
}
