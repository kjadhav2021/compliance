# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_7
class compliance::windows::item::w_7 {
  local_security_policy { 'EnableGuestAccount':
    ensure       => present,
    policy_value => '0',
  }
}
