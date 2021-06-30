# compliance::windows::item::w_8
#
# **Title:** Configure required services only
#
# **Description:** A default OS installation enables some non-essential services. Below are the
#                  list of services that require attention.
#
# **Impact:** Someservices have vulnerabilities and risks and can lead to unauthorized access or denial of service.
#
# **Risk Rating:** Medium/Low (varies as per individual risk as per SCD)
#
# **Standard Setting:** Click Start > Run and type services.msc
#                       Configure the list of services as given in SCD
#
# @param services services that need to be enforced
# @param report_only Whether or not to set the resources to noop mode
class compliance::windows::item::w_8 (
  Hash $services,
  Boolean $report_only = true,
  ){

  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug',
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
