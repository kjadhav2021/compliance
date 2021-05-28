# @summary A short summary of the purpose of this defined type.
#
# A description of what this defined type does
#
# @example
#   compliance::windows::regedit_entry { 'namevar': }
define compliance::windows::regedit_entry (
  String $registry_key,
  String $type,
  String $value,
) {
  registry_value { $registry_key:
    ensure => present,
    type   => $type,
    data   => $value,
  }
}
