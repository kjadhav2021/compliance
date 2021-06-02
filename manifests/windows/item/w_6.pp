# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_6
class compliance::windows::item::w_6 (
  Boolean $report_only = true,
  String $community_string = 'TEJAq0jPaNXOUlDSyBdp',
  String $community_type = '0x00000004',
) {

$registry_path="HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities\\"

  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_6'
  $item_title   = 'Secure the SNMP service settings'
  $setting_desc = 'Use complex community strings'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------

  if $facts['windows_features'] and 'SNMP-Service' in $facts['windows_features'] {
    registry_value { "${registry_path}${community_string}" :
    ensure => present,
    type   => 'dword',
    data   => $community_type,
    }
  }
  else {
    notify{ compliance::policy_title($item_id, $item_title, 'SNMP not enabled or installed', ''):
      message => 'Missing-Deps',
    }
  }
}
