# compliance::mssql::item::mssql_6
#
# **Title:** Disable or rename SA account
#
# **Description:** SA account is the administrative account in SQL. It is a well-known username which is frequently targeted.
#
# **Impact:** SA account can be used for gaining malicious access to SQL server and gain admin privileges on the Windows Server
# by using commands such as xp_cmdshell.
#
# **Risk Rating:** High
#
# **Standard Setting:** SA account should be disable or rename
#                       a. Disable
#                       ALTER LOGIN sa DISABLE
#                       b. Rename
#                       ALTER LOGIN sa WITH NAME = saforapps;
#
# @param report_only Whether or not to set the resources to noop mode
class compliance::mssql::item::mssql_6 (
  Boolean $report_only = true,
){
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug',
  }

  $item_id      = 'mssql_6'
  $item_title   = 'Disable or rename SA account'
  $setting_desc = 'SA account is the administrative account in SQL. It is a well-known username which is frequently targeted.
  SA account can be used for gaining malicious access to SQL server and gain admin privileges on the Windows Server by using commands such as xp_cmdshell' # lint:ignore:140chars

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------

  # Resource to connect to the DB instance
  # sqlserver::config { 'SQLEXPRESS':
  #   admin_login_type => 'WINDOWS_LOGIN',
  #   instance_name    => 'SQLEXPRESS',
  # }
  # sqlserver::login { 'sa':
  #   login    => 'sa',
  #   instance => 'SQLEXPRESS',
  #   disabled => true,
  #   require  => Sqlserver::Config['SQLEXPRESS'],
  # }
  sqlserver_tsql{ 'disable or rename sa account':
    instance => 'SQLEXPRESS',
    command  => 'ALTER LOGIN sa DISABLE; ALTER LOGIN sa WITH NAME = saforapps;',
    onlyif   => "IF (SELECT count(*) FROM sys.server_principals where name ='sa' or (name ='sa' and is_disabled='1')) >= 1  THROW 100000, 'sa user exists,rename it to saforapps', 1",# lint:ignore:140chars
  }
}
