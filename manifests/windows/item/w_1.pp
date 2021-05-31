# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_1
class compliance::windows::item::w_1 (
  Boolean $report_only    = true,
) {
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_1'
  $item_title   = 'Setup the server using NTFS file system'
  $setting_desc = 'Ensure file system drive in NTFS'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  # $facts['drive'].filter |$_k,$d| { $d['filesystem'] != 'NTFS' or $d['filesystem'] != '' }.each |$k,$d| {
  #   notify{ bnm_compliance::policy_title($item_id, $item_title, "${setting_desc} ${k}", ''):
  #     message => 'Non-Compliant',
  #   }
  # }
  if $facts['filesystem'] {
    $facts['filesystem'].each |$drive| {
      notify{ $drive.split(' ')[0]:}
      notify{ 'facts value':}
      notify{ $drive.split(' ')[1]:}
    }
    }
}
