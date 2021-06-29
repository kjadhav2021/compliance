# compliance::windows::item::w_16
#
# **Title:** Secure the permissions to critical system files
#
# **Description:** Only authorized users should access critical files.
#
# **Impact:** Critical system files can be modified leading to non-availability of system and unauthorized access to critical data.
#
# **Risk Rating:** Medium
#
# **Standard Setting:** Restrict access on system files for specific users/groups with appropriate
# permissions. Everyone group should not be configured with full control permission.
# Go to My Computer > Tools > Folder Option > View
# Enable Show hidden file and folder
# Uncheck Hide protected operating system files
# In c:\ now we can see the (boot.ini, ntdetect.com, ntldr) files
# Right Click the files and go to Properties > Security and set the permissions
#
#
# @param report_only Whether or not to set the resources to noop mode
# @param directories_acl directories acl map
class compliance::windows::item::w_16 (
  Boolean $report_only      = true,
  Hash    $directories_acl  = {
                                $facts['windows_env']['WINDIR'] => [
                                  { 'identity' => 'CREATOR OWNER', 'rights' => [ 'full' ] },
                                  { 'identity' => 'NT AUTHORITY\\SYSTEM', 'rights' => [ 'full' ] },
                                  { 'identity' => 'BUILTIN\\Administrators', 'rights' => [ 'full' ] },
                                  { 'identity' => 'BUILTIN\\Users', 'rights' => [ 'read', 'execute' ] } ],
                                "${facts['system32']}/LogFiles" =>  [
                                  {'rights' => ['read'], 'identity' => 'Everyone' },
                                  {'rights' => ['full'], 'identity' => 'NT AUTHORITY\\SYSTEM' },
                                  {'rights' => ['full'], 'identity' => 'BUILTIN\\Administrators' } ]
                              }
) {
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_16'
  $item_title   = 'Secure the permissions to critical system files'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  $directories_acl.each |$k, $d| {
    $setting_desc = "${k} shares"
    acl { compliance::policy_title($item_id, $item_title, $setting_desc, "${k}-${d}"):
      name                       => $k,
      inherit_parent_permissions => false,
      permissions                => $d,
      purge                      => true,
    }
  }
}
