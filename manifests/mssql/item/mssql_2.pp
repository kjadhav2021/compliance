# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::mssql::item::mssql_2
class compliance::mssql::item::mssql_2 {
}
# (Get-Acl 'HKLM:Software\Microsoft\Microsoft SQL Server').PurgeAccessRules([System.Security.Principal. NTAccount] 'Everyone')
#$acl = Get-Acl 'HKLM:Software\Microsoft\Microsoft SQL Server' ; $usersid = New-Object System.Security.Principal.Ntaccount ("Everyone") ;$acl.PurgeAccessRules($usersid)
