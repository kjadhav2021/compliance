# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_6
class compliance::windows::item::w_6 (
  String $securesnmpkey,
  String $securesnmpvalue,
) {
  registry_value { $securesnmpkey :
    ensure => present,
    type   => 'dword',
    data   => $securesnmpvalue,
  }
}
