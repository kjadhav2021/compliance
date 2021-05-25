# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_2
class compliance::windows::item::w_2 (
  String  $system_timezone   = 'Singapore Standard Time',
){
  class { 'timezone_win':
  timezone => $system_timezone,
  }
}
