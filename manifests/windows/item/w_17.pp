# compliance::windows::item::w_17
#
# **Title:** Disable Autorun on drives
#
# **Description:** A default OS installation enables autorun on CD-ROM and other drives. Autorun feature of a CD-ROM or
# other drive presents a potential security threat by automatically running code when a CD is inserted into a machine.
#
# **Impact:** Automatic execution of programs can lead to denial of service or unauthorized control of system.
#
# **Risk Rating:** Low
#
# **Standard Setting:** Disable Autorun on CD-ROM and all other Drives.
# Click Start > Run and type regedit Go to the registry hive:
#               HKEY_LOCAL_MACHINE\ SYSTEM\CurrentControlSet\Services\CDROM\AutoRun = '0XFF'
#               HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun = '0XFF'
# **Note:** Screen saver password is required for servers located outside from Data Centre.
#
#
# @param report_only Whether or not to set the resources to noop mode
# @param policy_value1 autorun registry value '0XFF'
# @param policy_value2 NoDriveTypeAutoRun registry value '0XFF'
class compliance::windows::item::w_17 (
  Boolean $report_only = true,
  String $policy_value1 = '0xFF',
  String $policy_value2 = '0xFF',
){
# The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug',
  }

  $item_id      = 'w_18'
  $item_title1   = 'Disable Autorun on drives'
  $setting_desc1 = 'Disable Autorun on CD drives'
  $item_title2   = 'Disable Autorun all drives'
  $setting_desc2 = 'Disable Autorun on all drives'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  registry_value { compliance::policy_title($item_id,$item_title1,$setting_desc1,$policy_value1) :
    ensure => present,
    path   => 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CDROM\\AutoRun',
    type   => 'dword',
    data   => $policy_value1,
  }
  registry_value { compliance::policy_title($item_id,$item_title2,$setting_desc2,$policy_value2) :
    ensure => present,
    path   => 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun',
    type   => 'dword',
    data   => $policy_value2,
  }
}
