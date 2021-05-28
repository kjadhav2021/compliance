# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_5
class compliance::windows::item::w_5 {
  # $registry_titles = [ $::screensaverissecuretitle, $::screensavertimeouttitle]
  $registry_keys = [ $::screensaverissecurekey,$::screensavertimeoutkey]
  $registry_values = [$::screensaverissecurevalue,$::screensavertimeoutvalue]

  if $facts['cis_local_sids'] {
    $facts['cis_local_sids'].each |$sid| {
      registry_value { "HKEY_USERS\\${sid}${registry_keys}":
        ensure => present,
        type   => 'string',
        data   => $registry_values,
      }
    }
  }
}
