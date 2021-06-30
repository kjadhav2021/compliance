# compliance::windows::item::w_14
#
# **Title:** Allocate adequate space for the for Event viewer logs
#
# **Description:** All system-generated messages are logged and can be viewed using event
#                  viewer.
#
# **Impact:** Critical logs might get overwritten in the absence of sufficient event viewer file size.
#
# **Risk Rating:** Medium
#
# **Standard Setting:** Set event viewer files size as mentioned in the following:
# Click Start > Run and type eventvwr.msc
# Right click on Application/ Security/ System, choose the Properties and set the Maximum Log Size 30MB
# Set the Security Log Near Capacity Warning to 90%. This is the Percentage threshold for the security event log when
# the system will generate a warning. Click Start > Run and type regedit Go to the registry hive:
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security and set the registry key settings as mentioned in the table below.
#
#
# @param report_only Whether or not to set the resources to noop mode
# @param events_type event types map
class compliance::windows::item::w_14 (
  Boolean $report_only  = true,
  Hash $events_type  = { 'Application' => { 'MaxSize' => '33554432','Retention' => '0','setting_desc' => '32768 kilobytes'},
                            'Security' => { 'MaxSize' => '33554432','Retention' => '0','WarningLevel' => '90',
                                            'setting_desc' => '32768 kilobytes, WarningLevel 90%'},
                            'System' => { 'MaxSize' => '33554432','Retention' => '0','setting_desc' => '32768 kilobytes'},},
  Boolean $gpo = false,
) {
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug',
  }

  $item_id      = 'w_14'
  $item_title   = 'Event viewer logs space'
  $setting_desc = 'All system-generated messages'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  $events_type.each |$k, $d| {
    if $gpo {
      $parent_key = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\${k}"
      if !defined( Registry_key[$parent_key] ) {
        registry_key { $parent_key:
          ensure => present,
        }
      }
    }
    ($d.keys - 'setting_desc').each |$d1| {
      if $gpo {
        $path_key = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\${k}\\${d1}"
      } else {
        $path_key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\${k}\\${d1}"
      }
      registry_value { compliance::policy_title($item_id, "${k} log size", $d['setting_desc'], "${d[$d1]} "):
        ensure => present,
        path   => $path_key,
        type   => 'dword',
        data   => $d[$d1],
      }
    }
  }
}
