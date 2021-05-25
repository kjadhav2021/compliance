# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_2
class compliance::windows::item::w_2 (
  String  $system_timezone   = 'Malay Peninsula Standard Time',
){
  local_security_policy { 'Change the time zone':
    ensure       => present,
    policy_value => $system_timezone,
  }
}
