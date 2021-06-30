# compliance::windows::item::w_20
#
# **Title:** Disable/Lockdown USB devices
#
# **Description:** To avoid unnecessary data theft, while also protecting against malware
#                  introduced by employees’ devices.
#
# **Impact:** Data theft and introduce of malware.
#
# **Risk Rating:** High
#
# **Standard Setting:**
# 1) Logon to the domain controller as a domain administrator equivalent account
# 2) Click on the Windows icon in the lower left corner and the Server Manager
# 3) Click on Tools on the upper right hand side
# 4) Click Group Policy Management
# 5) Drill down through the Group Policy Management located at left pane until reach Default Domain Policy.
# 6) Right click on Default Domain Policy and select Edit. Group Policy Management Editor will be opened.
# 7) Drill down through the policy setting on the left pane to Computer Configuration > Policies > Administrative Templates > 
# System > Device Installation Restrictions
# 8) In the right pane double click on the Prevent Installation of Removable Devices. Click the Enabled radio button and click OK.
#
# **Note:** Screen saver password is required for servers located outside from Data Centre.
#
#
# @param report_only Whether or not to set the resources to noop mode
# @param policy_value1 Disable/Lockdown USB devices-all users registry value 0x00000001
# @param policy_value2 Disable/Lockdown USB devices-admin users registry value 0x00000000
class compliance::windows::item::w_20 (
  Boolean $report_only = true,
  String $policy_value1 = '0x00000001',
  String $policy_value2 = '0x00000000',
){
# The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug',
  }

  $item_id      = 'w_20'
  $item_title   = 'Disable/Lockdown USB devices'
  $setting_desc1 = 'Disable/Lockdown USB devices-all users'
  $setting_desc2 = 'Disable/Lockdown USB devices-admin users'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  registry_value { compliance::policy_title($item_id,$item_title,$setting_desc1,$policy_value1) :
    ensure => present,
    path   => 'HKLM\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions\\DenyRemovableDevices',
    type   => 'dword',
    data   => $policy_value1,
  }
  registry_value { compliance::policy_title($item_id,$item_title,$setting_desc2,$policy_value2) :
    ensure => present,
    path   => 'HKLM\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions\\AllowAdminInstall',
    type   => 'dword',
    data   => $policy_value2,
  }
}
