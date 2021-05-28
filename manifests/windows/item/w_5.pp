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
      notify{ $sid:}
      notify{ $registry_keys: }
      notify{ $registry_values: }
    }
  }
}
