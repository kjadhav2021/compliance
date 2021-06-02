# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows
class compliance::windows (
  Boolean $report_only                = true,
  Array   $skipped_items              = []
){
  $standard = '::compliance::windows::item'
  $items = [
    'w_1'
    # 'w_2',
    # 'w_3',
    # 'w_4',
    # 'w_5',
    # 'w_6',
    # 'w_7',
    # 'w_8',
    # 'w_9',
    # 'w_10',
    # 'w_11',
    # 'w_12',
    # 'w_13',
    # 'w_14',
    # 'w_15',
    # 'w_16',
    # 'w_17',
    # 'w_18',
    # 'w_19',
    # 'w_20',
    # 'w_21'
  ]

  case $facts['operatingsystemmajrelease'] {
    '2012 R2', '2012', '2016', '2019' : {
      $process_item = $items - $skipped_items
    }
    default: {
      warning('N/A - Security compliance standard is implemented for this OS')
    }
  }
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
