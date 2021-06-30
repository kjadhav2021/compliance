# compliance::windows::item::w_5
#
# **Title:** Enable the screen saver password [Optional]
#
# **Description:** Windows server locks the console after a particular period of inactivity and
#                  requires authentication for unlocking the console.
#
# **Impact:** An intruder can use an unattended console for manipulating system settings for gaining unauthorized access.
#
# **Risk Rating:** Medium
#
# **Standard Setting:** Set the screen server password and screen saver timeout to 15 minutes.
#                       Right click on Desktop, select Properties and under the Screen Saver tab set the screen saver settings
#                       Also set ‘On resume password protect’ checkbox
#
# **Note:** Screen saver password is required for servers located outside from Data Centre.
#
#
# @param report_only Whether or not to set the resources to noop mode
# @param screensaverissecuredata 1 or 0 to enable and disable screensaver
# @param screensavertimeoutdata default timeout settings 15 mins
class compliance::windows::item::w_5 (
  Boolean $report_only = true,
  String $screensaverissecuredata = '1',
  String $screensavertimeoutdata = '900',
){
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug',
  }

  $item_id      = 'w_5'
  $item_title   = 'Enable the screen saver password'
  $setting_desc = 'Screen saver password is required for servers outside of data centres'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------

  if $facts['cis_local_sids'] {
    $facts['cis_local_sids'].each |$sid| {
      registry::value { "HKEY_USERS\\${sid}\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop:ScreenSaverIsSecure": # lint:ignore:140chars
        key   => "HKEY_USERS\\${sid}\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop",
        value => 'ScreenSaverIsSecure',
        type  => string,
        data  => $screensaverissecuredata,
      }
      registry::value { "HKEY_USERS\\${sid}\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop:ScreenSaveTimeOut": # lint:ignore:140chars
        key   => "HKEY_USERS\\${sid}\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop",
        value => 'ScreenSaveTimeOut',
        type  => string,
        data  => $screensavertimeoutdata,
      }
    }
  }
}
