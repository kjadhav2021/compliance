# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_5
class compliance::windows::item::w_5 {
  # $registry_titles = [ $::screensaverissecuretitle, $::screensavertimeouttitle]
  # $registry_keys = [ $::screensaverissecurekey,$::screensavertimeoutkey]
  # $registry_values = [$::screensaverissecurevalue,$::screensavertimeoutvalue]

  if $facts['cis_local_sids'] {
    $facts['cis_local_sids'].each |$sid| {
      registry::value { "HKEY_USERS\\${sid}\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop:ScreenSaverIsSecure": # lint:ignore:140chars
        key   => "HKEY_USERS\\${sid}\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop",
        value => 'ScreenSaverIsSecure',
        type  => string,
        data  => '1',
      }
      registry::value { "HKEY_USERS\\${sid}\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop:ScreenSaveTimeOut": # lint:ignore:140chars
        key   => "HKEY_USERS\\${sid}\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop",
        value => 'ScreenSaveTimeOut',
        type  => string,
        data  => '900',
      }
    }
  }
}
