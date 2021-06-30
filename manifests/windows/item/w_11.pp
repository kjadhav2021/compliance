# bnm_compliance::windows::item::w_11
#
# **Title:** Enable Auditing and Logging
#
# **Description:** Windows Server 2016 provides us Advance Audit Policy Configuration function.
# It can be used to provide detailed control over audit policies, identify attempted or successful attacks on your network
# and resources, and verify compliance with rules governing the management of critical organizational assets.
#
# **Impact:** Unauthorized activities can go undetected.
#
# **Risk Rating:** High
#
# **Standard Setting:**
#
# **Note:** When Advanced Audit Policy Configuration settings are used, the “Audit: Force audit policy subcategory settings
#           (Windows Vista or later) to override audit policy category settings” policy setting under Local Policies\Security
#           Options must also be enabled.
#
#
# @param report_only Whether or not to set the resources to noop mode
# @param audit_items audit and logging events map
#
##
class compliance::windows::item::w_11 (
  Boolean $report_only = true,
  Hash    $audit_items = { 'Audit Other Account Logon / Logoff Events' => {
                                'subcategory'   => 'Other Logon/Logoff Events',
                                'policy_value'  => 'Success,Failure' },
                              'Audit User Account Management' => {
                                'subcategory'   => 'User Account Management',
                                'policy_value'  => 'Success,Failure' },
                              'Audit Directory Service Access' => {
                                'subcategory'         => 'Directory Service Access',
                                'domain_policy_value' => 'Success,Failure',
                                'policy_value'        => 'No auditing' },
                              'Audit Directory Service Changes' => {
                                'subcategory'   => 'Directory Service Changes',
                                'domain_policy_value' => 'Success,Failure',
                                'policy_value'        => 'No auditing' },
                              'Audit Logon' => {
                                'subcategory'   => 'Logon',
                                'policy_value'  => 'Success,Failure' },
                              'Audit Policy Change' => {
                                'subcategory'   => 'Audit Policy Change',
                                'policy_value'  => 'Success,Failure' },
                              'Audit Sensitive Privilege Use' => {
                                'subcategory'   => 'Sensitive Privilege Use',
                                'policy_value'  => 'Success,Failure' },
                              'Audit Credential Validation' => {
                                'subcategory'   => 'Credential Validation',
                                'policy_value'  => 'Success,Failure' },
                              'Audit Computer Account Management' => {
                                'subcategory'   => 'Computer Account Management',
                                'policy_value'  => 'Success' },
                              'Audit Other Account Management Events' => {
                                'subcategory'   => 'Other Account Management Events',
                                'policy_value'  => 'Success,Failure' },
                              'Audit Security Group Management' => {
                                'subcategory'   => 'Security Group Management',
                                'policy_value'  => 'Success,Failure' },
                              'Audit Process Creation' => {
                                'subcategory'   => 'Process Creation',
                                'policy_value'  => 'Success' },
                              'Audit Account Lockout' => {
                                'subcategory'   => 'Account Lockout',
                                'policy_value'  => 'Success' },
                              'Audit Logoff' => {
                                'subcategory'   => 'Logoff',
                                'policy_value'  => 'Success' },
                              'Audit Special Logon' => {
                                'subcategory'   => 'Special Logon',
                                'policy_value'  => 'Success' },
                              'Audit Authentication Policy Change' => {
                                'subcategory'   => 'Authentication Policy Change',
                                'policy_value'  => 'Success' },
                              'Audit Security State Change' => {
                                'subcategory'   => 'Security State Change',
                                'policy_value'  => 'Success,Failure' },
                              'Audit Security System Extension' => {
                                'subcategory'   => 'Security System Extension',
                                'policy_value'  => 'Success,Failure' },
                              'Audit System Integrity' => {
                                'subcategory'   => 'System Integrity',
                                'policy_value'  => 'Success,Failure' }
                            }
) {
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug',
  }

  $item_id      = 'w_11'
  $item_title   = 'Enable Auditing and Logging'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  $audit_items.each |$k,$d| {
    if $d['domain_policy_value'] and str2bool($facts['windows_is_domain_controller']) {
      $value = $d['domain_policy_value']
    } else {
      $value = $d['policy_value']
    }
    auditpol { compliance::policy_title($item_id, $k, '', "${value} "):
      subcategory  => $d['subcategory'],
      policy_value => $value,
    }
  }
}
