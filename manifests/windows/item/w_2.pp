# compliance::windows::item::w_2
#
# **Title:** Configure the time zone
#
# **Description:** Time zone setting provides the reference in the enterprise for all activities
#                  that are logged in a system.
#
# **Impact:** Correlation of logs and establishment of timeline for any malicious activity detected cannot be done.
#
#
# **Risk Rating:** Low
#
# **Standard Setting:** Set time zone to GMT+8:00.
#
# **Note:** Double click on the Clock in the Task Bar and select Time Zone tab to set the time zone settings
#
#
# @param report_only Whether or not to set the resources to noop mode
class compliance::windows::item::w_2 (
  Boolean $report_only    = true,
  String  $system_timezone = 'Singapore Standard Time',
){
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_2'
  $item_title   = 'Configure the time zone'
  $setting_desc = '(UTC+08:00) Kuala Lumpur, Singapore - Singapore Standard Time'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  if $facts['timezone'] {
    if $facts['timezone'] != 'Singapore Standard Time' {
      if $report_only {
      notify{ compliance::policy_title($item_id, $item_title, setting_desc, 'timezone has configured incorrectly'):
        message => 'Non-Compliant',}
      }
    else {
      class { 'timezone_win':
      timezone => $system_timezone,
      }
    }
    }
  }
  else {
    notify{ compliance::policy_title($item_id, $item_title, 'Invalid facts', ''):
      message => 'Missing-Deps',
    }
  }
}
