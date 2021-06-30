# compliance::windows::item::w_3
#
# **Title:** Install service pack and patches
#
# **Description:** Service packs and patches provide the OS enhancements and latest updates against vulnerabilities.
#                  Security Patches to be deployed in line with the requirement stipulated in the Patch Management Procedure.
#
# **Impact:** System vulnerabilities when exploited could result to system compromised,
#             unauthorised elevation of privilege, loss of data/ data integrity as well as denial of service.
#
# **Risk Rating:** Medium
#
# **Standard Setting:** Download and install service pack and patches from the following URL:
#                        http://support.microsoft.com/default.aspx?scid=fh;en-us;sp
#
# **Note:** Latest service pack and patches are required for initial server installation.
#           Subsequent updates depends on the Patch Management Procedure requirements.
#
#
# @param report_only Whether or not to set the resources to noop mode
class compliance::windows::item::w_3(
  Boolean $report_only = true,
) {
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug',
  }

  $item_id      = 'w_3'
  $item_title   = 'Install service pack and patches'
  $setting_desc = 'Ensure system has patched with latest updates'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  if $facts['pe_patch'] {
    if $facts['pe_patch']['package_update_count'] > 0 or $facts['pe_patch']['security_package_update_count'] > 0 {
      notify { compliance::policy_title($item_id, $item_title, $setting_desc, "Package Update Count:
      ${facts['pe_patch']['package_update_count']}, Security Package Update Count: ${facts['pe_patch']['security_package_update_count']}"):# lint:ignore:140chars
        message => 'Non-Compliant',
      }
    }
  } else {
    notify { compliance::policy_title($item_id, $item_title, $setting_desc, 'PE patch not eabled for this node'):
      message => 'Non-Compliant',
    }
  }
}
