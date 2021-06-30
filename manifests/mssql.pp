# @summary compliance list for sql server
#
# SQL server compliance
#
# @example
#   include compliance::mssql
class compliance::mssql (
  Boolean $report_only                = true,
  Array   $skipped_items              = []
){
  $standard = '::compliance::mssql::item'
  $items = [
    'mssql_1'
    # 'mssql_2',
    # 'mssql_3',
    # 'mssql_4',
    # 'mssql_5'
  ]

  # case $facts['operatingsystemmajrelease'] {
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