# @summary
# 14.Allocate adequate space for the for Event viewer logs
#
# @example
#   include compliance::windows::item::w_14
class compliance::windows::item::w_14 (
  Boolean $report_only                = true,
  Hash    $events_type                = { 'Application' =>  { 'MaxSize'       => '33554432',
                                                              'Retention'     => '0',
                                                              'setting_desc'  => '32768 kilobytes'
                                                            },
                                          'Security'    =>  { 'MaxSize'       => '33554432',
                                                              'Retention'     => '0',
                                                              'WarningLevel'  => '90',
                                                              'setting_desc'  => '32768 kilobytes, WarningLevel 90%'
                                                            },
                                          'System'      =>  { 'MaxSize'       => '33554432',
                                                              'Retention'     => '0',
                                                              'setting_desc'  => '32768 kilobytes'
                                                            },
                                        },
  Boolean $gpo                        = false,
) {
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
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
      registry_value { bnm_compliance::policy_title($item_id, "${k} log size", $d['setting_desc'], "${d[$d1]} "):
        ensure => present,
        path   => $path_key,
        type   => 'dword',
        data   => $d[$d1],
      }
    }
  }
}
