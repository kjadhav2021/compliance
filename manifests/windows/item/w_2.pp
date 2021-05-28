# @summary
#
# enforce the timezone on target node machine
#
# @example
#   include compliance::windows::item::w_2
class compliance::windows::item::w_2 (
  String  $system_timezone,
){
  class { 'timezone_win':
    timezone => $system_timezone,
  }
}
