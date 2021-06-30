# compliance::windows::item::w_6
#
# **Title:** Secure the SNMP service settings [If SNMP is installed or enabled]
#
# **Description:** SNMP protocol helps in server monitoring and management. SNMP
#                 community strings acts like a password to access the system. By default they are ‘Public’.
#
# **Impact:** The default strings assist in unauthorized access.
#
# **Risk Rating:** Medium
#
# **Standard Setting:** Use complex community strings.
#
# @param report_only Whether or not to set the resources to noop mode
# @param community_string complex string for community name instead of public
# @param community_type community type ie Read-only, Read-Write and snmp Trap

class compliance::windows::item::w_6 (
  Boolean $report_only = true,
  String $community_string = 'TEJAq0jPaNXOUlDSyBdp',
  String $community_type = '0x00000004',
) {

$registry_path = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities\\"

  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug',
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
    notify { compliance::policy_title( $item_id, $item_title, 'SNMP not enabled or installed', ''):
      message => 'Missing-Deps',
    }
  }
}
