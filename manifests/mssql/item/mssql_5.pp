# compliance::mssql::item::mssql_5
#
# **Title:** Remove Guest User ID from the database
#
# **Description:** The guest user ID in a database allows access by all login IDs
#
# **Impact:** If the user ID guest exists in the database, all logins not mapped or aliased to a user ID are allowed access to the
# database as guest. The guest account cannot be removed from the master, msdb, model, tempdb and distribution databases.
# The use of the guest user ID in other databases should be limited.
#
# **Risk Rating:** High
#
# **Standard Setting:** Revoke CONNECT permission of the Guest user to user
#                       a. Go to Start > Programs > Microsoft SQL Server > Management
#                          Studio
#                       b. Launch a new query window
#                       c. Paste the following command into the window and change the
#                          database name as you go use [AdventureWorks2008]
#                       go
#                          REVOKE CONNECT FROM GUEST
#
# @param report_only Whether or not to set the resources to noop mode
class compliance::mssql::item::mssql_5 {
  # Resource to connect to the DB instance
  sqlserver::config { 'SQLEXPRESS':
    admin_login_type => 'WINDOWS_LOGIN'
  }
  ~> sqlserver::user {'guest':
    login       => 'guest',
    permissions => 'REVOKE',
  }
  ~> sqlserver::login::permissions { 'guest':
    login => 'guest',
    state => 'REVOKE',
  }
}
