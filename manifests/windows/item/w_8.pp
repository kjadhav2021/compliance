# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_8
class compliance::windows::item::w_8 (
  Hash $services,
  Boolean $report_only = true,
  ){

  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_8'
  $item_title   = 'Configure only required services'
  $setting_desc = 'Configure required services using services.msc'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  Service{
    provider => 'windows',
  }
  create_resources(service,$services)
}
