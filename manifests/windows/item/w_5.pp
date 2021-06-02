# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_5
class compliance::windows::item::w_5 (
  Boolean $report_only    = true,
  String $screensaverissecuredata = '1',
  String $screensavertimeoutdata = '900',
){
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_5'
  $item_title   = 'Enable the screen saver password'
  $setting_desc = 'Screen saver password is required for servers outside of data centres'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------

  if $facts['cis_local_sids'] {
    $facts['cis_local_sids'].each |$sid| {
      registry::value { "HKEY_USERS\\${sid}\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop:ScreenSaverIsSecure": # lint:ignore:140chars
        ensure => present,
        key    => "HKEY_USERS\\${sid}\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop",
        value  => 'ScreenSaverIsSecure',
        type   => string,
        data   => $screensaverissecuredata,
      }
      registry::value { "HKEY_USERS\\${sid}\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop:ScreenSaveTimeOut": # lint:ignore:140chars
        ensure => present,
        key    => "HKEY_USERS\\${sid}\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop",
        value  => 'ScreenSaveTimeOut',
        type   => string,
        data   => $screensavertimeoutdata,
      }
    }
  }
}
