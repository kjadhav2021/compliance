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
  $standard = 'compliance::mssql::item'
  $items = ['mssql_1','mssql_6']

  # Need to write logic to compare the versions of SQL server 2012, 2016, and 2019
  $process_item = $items - $skipped_items
  # Include all items
  $process_item.each |$item| {
    class { "${standard}::${item}":
      report_only => $report_only,
    }
  }
}
