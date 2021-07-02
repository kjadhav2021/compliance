# compliance::mssql::item::mssql_1
#
# **Title:** Configure strong permissions on MSSQL registry keys
#
# **Description:** Everyone group must be restricted to read permission or no permission for the following registry key:
#                  HKLM\Software\Microsoft\Microsoft SQL Server
#
# **Impact:** Critical system information including login mode, auditing level, and configurations are stored in the registry under SQL
# registry keys. Loose permissions can lead to unauthorized access resulting in denial of service or loss of data confidentiality.
#
# **Risk Rating:** High
#
# **Standard Setting:** Restrict registry access to the accounts that MSSQLServer and SQLServerAgent use.
#                       a. Select Start/Run
#                       b. Type regedt32 and click OK
#                       c. On the Registry Editor window, select the following registry keys:
#                       d. HKEY_LOCAL_MACHINE\Software\Microsoft\Microsoft SQL Server
#                       e. Select Permissions and remove everyone group
#
#
# @param report_only Whether or not to set the resources to noop mode
class compliance::mssql::item::mssql_1 (
  Boolean $report_only    = true,
){
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug',
  }

  $item_id      = 'mssql_1'
  $item_title   = 'Configure strong permissions on MSSQL registry keys'
  $setting_desc = 'Everyone group must be removed from permissions for HKLM\Software\Microsoft\Microsoft SQL Server' # lint:ignore:140chars

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  # Resource to enforce compliance item mssql_1
  exec { compliance::policy_title($item_id, $item_title, $setting_desc):
    command  => '$acl = Get-Acl \'HKLM:Software\Microsoft\Microsoft SQL Server\' ; $usersid = New-Object System.Security
                .Principal.Ntaccount (\'Everyone\') ;$acl.PurgeAccessRules($usersid); $acl | set-acl',
    provider => powershell,
  }
}
