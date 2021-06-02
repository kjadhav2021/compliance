# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_15
class compliance::windows::item::w_15 (
  Boolean         $report_only            = true,
  Hash            $permitted_shares       = { 'Downloads' => { 'Everyone' =>
                                              { 'access_control_type' => 'Allow', 'access_right' => 'Read'} } },
  Array[String]   $skipped_shares         = [ 'ADMIN$', 'IPC$', 'print$' ],
  Boolean         $skipped_drives_shares  = true,
) {
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_15'
  $item_title   = 'Assign secure permissions to shares'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  if $facts['windows_shares'] and $facts['drive'] {
    if skipped_drives_shares {
      $shares_drive = $facts['drive'].keys.map |$k| { "${k[0]}$" }
    } else {
      $shares_drive = []
    }
    ($facts['windows_shares'] - $shares_drive - $skipped_shares).each |$s, $d| {
      if $permitted_shares[$s] and $permitted_shares[$s] != $d['permissions'] {
        $setting_desc = "${s} invalid shares permission ${$d['permissions']}"
        if $report_only {
          notify{ compliance::policy_title($item_id, $item_title, $setting_desc, "${s}-${d['permissions']}"):
            message => 'Non-Compliant',
          }
        } else {
          # Rebuild shares
          exec { compliance::policy_title($item_id, $item_title, $setting_desc, "${s}-${d['permissions']}"):
            command  => "exit (Remove-SmbShare -Name '${s}' -Force).ReturnValue",
            provider => powershell,
          }
        }
      } elsif $permitted_shares[$s] == undef {
        $setting_desc = "${s} non-permitted shares"
        if $report_only {
          notify{ compliance::policy_title($item_id, $item_title, $setting_desc, "${s}-${d['permissions']}"):
            message => 'Non-Compliant',
          }
        } else {
          exec { compliance::policy_title($item_id, $item_title, $setting_desc, "${s}-${d['permissions']}"):
            command  => "exit (Remove-SmbShare -Name '${s}' -Force).ReturnValue",
            provider => powershell,
          }
        }
      }
    }
  } else {
    notify{ compliance::policy_title($item_id, $item_title, 'Invalid facts', ''):
      message => 'Missing-Deps',
    }
  }
}
