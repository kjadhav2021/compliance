# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_3
class compliance::windows::item::w_3(
  Boolean $report_only    = true,
) {
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_3'
  $item_title   = 'Install service pack and patches'
  $setting_desc = 'Ensure system has patched with latest updates'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  if $facts['pe_patch'] {
    if $facts['pe_patch']['package_update_count'] > 0 or $facts['pe_patch']['security_package_update_count'] > 0 {
      notify{ compliance::policy_title(
                $item_id,
                $item_title,
                $setting_desc,
                "Package Update Count: ${facts['pe_patch']['package_update_count']},
                Security Package Update Count: ${facts['pe_patch']['security_package_update_count']}"):
        message => 'Non-Compliant',
      }
    }
  } else {
    notify{ compliance::policy_title($item_id, $item_title, $setting_desc, 'PE patch not eabled for this node'):
      message => 'Non-Compliant',
    }
  }
}
