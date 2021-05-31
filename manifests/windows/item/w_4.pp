# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_4
class compliance::windows::item::w_4 (
Boolean $report_only    = true,
) {
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_4'
  $item_title   = 'Install Antivirus software'
  $setting_desc = 'Install antivirus software and configure regular updates'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  class { 'archive':
    seven_zip_name     => '7-Zip 19.00 (x64 edition)',
    seven_zip_source   => 'https://www.7-zip.org/a/7z1900-x64.msi',
    seven_zip_provider => 'windows',
  }
}
