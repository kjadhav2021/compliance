# compliance::windows::item::w_10
#
# **Title:** Disable all Non essential privileged accounts
#
# **Description:** Disable accounts not essential for system or application requirements.
#
#
# **Impact:** Non-essential user accounts assists in gaining unauthorized access.
#
# **Risk Rating:** Medium
#
# **Standard Setting:** Disable all accounts that do not meet system or application objectives.
#                       Click Start > Run and type compmgmt.msc
#                       Expand Local User & Groups > Users container and disable the non-essential accounts in the system
#
#
# @param report_only Whether or not to set the resources to noop mode
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
    unless   => ['Get-LocalUser Guest | format-table -property enabled -hidetableheaders','true']
  }
}
