# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_7
class compliance::windows::item::w_7 {
  exec { 'disable_guest':
    command  => 'Get-LocalUser Guest | Disable-LocalUser',
    provider => powershell,
  }
}
