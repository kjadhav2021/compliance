# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_7
class compliance::windows::item::w_7 {
  user { 'guest':
    ensure   => 'present',
    comment  => 'Built-in account for guest access to the computer/domain',
    groups   => ['BUILTIN\Guests'],
    provider => 'windows_adsi',
  }
}
