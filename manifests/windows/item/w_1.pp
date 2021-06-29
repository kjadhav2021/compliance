# compliance::windows::item::w_1
#
# **Title:** Setup the server using NTFS file system
#
# **Description:** NTFS is a secure file system that enables administrators to configure
#                  security features including discretionary access control and encrypted storage.
#
# **Impact:** Other file systems do not allow granular user permissions for files. This can lead to
#             unauthorized access to critical information.
#
# **Risk Rating:** Low
#
# **Standard Setting:** Make sure that all partitions on server are in NTFS format. If necessary, use the convert utility
#                       and convert FAT partitions to NTFS. Convert the FAT/FAT32 partition into NTFS
#
# **Note:** convert x: /fs:ntfs
#
#
# @param report_only Whether or not to set the resources to noop mode
# @param skips_drive skip drives from enforcement.
class compliance::windows::item::w_1 (
  Boolean $report_only       = true,
  Array[String] $skips_drive = ['C:']
) {
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_1'
  $item_title   = 'Setup the server using NTFS file system'
  $setting_desc = 'NTFS'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  if $facts['drive'] {
    #  excluding skips_drives items from $facts[drive] using minus operator
    ($facts['drive'].filter |$_k,$d| { $d['type'] == 'Fixed' and $d['filesystem'] != 'NTFS' } - $skips_drive).each |$k,$d| {
      if $report_only {
        notify { compliance::policy_title($item_id, $item_title, "${k}-${setting_desc}", "${k} - ${d['filesystem']}" ):
          message => 'Non-Compliant',
        }
      } else {
        exec { compliance::policy_title($item_id, $item_title, "${k}-${setting_desc}", "${k} - ${d['filesystem']}" ):
          path    => $facts['system32'],
          command => "cmd.exe /c echo|set /p=\"${d['volume_name']}\" | convert ${k} /fs:ntfs /X",
          unless  => "${facts['system32']}/WindowsPowershell/v1.0/powershell.exe 'if((Get-Volume ${k[0]}).FileSystem -ne \'NTFS\'){ exit 1 }'", # lint:ignore:140chars
        }
      }
    }
  } else {
    notify { compliance::policy_title($item_id, $item_title, 'Invalid facts', ''):
      message => 'Missing-Deps',
    }
  }
}
