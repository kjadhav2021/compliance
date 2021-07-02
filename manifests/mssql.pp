# @summary compliance list for sql server
#
# SQL server compliance
#
# @example
#   include compliance::mssql
class compliance::mssql (
  Boolean $report_only = true,
  Array   $skipped_items = [],
){
  $standard = '::compliance::mssql::item'
  $items = ['mssql_1','mssql_5','mssql_6']

  sqlserver::config { 'SQLEXPRESS':
    admin_login_type => 'WINDOWS_LOGIN',
    instance_name    => 'SQLEXPRESS',
  }

  # case $facts['operatingsystemmajrelease'] { # write logic to compare the versions of SQL server 2012, 2016, and 2019
  #   '2012 R2', '2012', '2016', '2019' : {
      $process_item = $items - $skipped_items
  # }
    # default: {
    #   warning('N/A - Security compliance standard is implemented for this OS')
    # }
  # }
  # Include all items
  if $report_only {
    $process_item.each |$item| {
      include "${standard}::${item}"
    }
  } else {
    $process_item.each |$item| {
      class { "${standard}::${item}":
        report_only => $report_only
      }
    }
  }
}
