# compliance::windows::item::w_18
#
# **Title:** Configure the system not to respond to name release command
#
# **Description:** This parameter determines whether the computer releases its NetBIOS
#                   name when it receives a name-release request from the network.
#
# **Impact:** Server is vulnerable to malicious name-release attack leading to Denial of Service.
#
# **Risk Rating:** Medium
#
# **Standard Setting:** Configure the system registry as show below:
#                       Click Start > Run and type regedit
#                       Go to the registry hive, create or set the registry key
#                       HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand = 1
#
# @param report_only Whether or not to set the resources to noop mode
#  @param policy_value registry value = 0x00000001
class compliance::windows::item::w_18 (
  Boolean $report_only = true,
  String $policy_value = '0x00000001',
){
# The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug',
  }

  $item_id      = 'w_18'
  $item_title   = 'Configure the system not to respond to name release command'
  $setting_desc = 'Configure the system not to respond to name release command'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  registry_value { compliance::policy_title($item_id,$item_title,$setting_desc,$policy_value) :
    ensure => present,
    path   => 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NetBT\\Parameters\\NoNameReleaseOnDemand',
    type   => 'dword',
    data   => $policy_value,
  }
}
