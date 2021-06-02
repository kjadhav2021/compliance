# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_21
class compliance::windows::item::w_21 (
  Boolean $report_only    = true,
  Hash $firewall_rules ={ 'domain_profile'  => [ {'firewall_state' => 'on'},
                                                      {'inbound_conn' => 'blockinbound'},
                                                      {'outbound_conn' => 'allowoutbound'},
                                                      {'disp_notification' => 'enable'},
                                                      {'allow_unicast' => 'disable'},
                                                      {'local_firewall_rules' => 'n/a (gpo-store only)'},
                                                      {'local_security_rules' => 'n/a (gpo-store only)'} ],
                                        'private_profile'  => [ {'firewall_state' => 'on'},
                                                      {'inbound_conn' => 'blockinbound'},
                                                      {'outbound_conn' => 'allowoutbound'},
                                                      {'disp_notification' => 'enable'},
                                                      {'allow_unicast' => 'disable'},
                                                      {'local_firewall_rules' => 'n/a (gpo-store only)'},
                                                      {'local_security_rules' => 'n/a (gpo-store only)'} ],
                                          'public_profile'  => [ {'firewall_state' => 'on'},
                                                      {'inbound_conn' => 'blockinbound'},
                                                      {'outbound_conn' => 'allowoutbound'},
                                                      {'disp_notification' => 'enable'},
                                                      {'allow_unicast' => 'disable'},
                                                      {'local_firewall_rules' => 'n/a (gpo-store only)'},
                                                      {'local_security_rules' => 'n/a (gpo-store only)'} ],},
) {
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_21'
  $item_title   = 'Enforce strong/proper configuration of Windows Firewall Policy'
  $setting_desc = 'Enforce strong/proper configuration of Windows Firewall Policy'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  $firewall_rules = lookup('compliance::windows::item::w_21::firewall_rules')
  $firewall_rules.each | $profile | {
    $rule_title = $profile[0]
    $firewall_state = $profile[1]['firewall_state']
    $inbound_conn = $profile[1]['inbound_conn']
    $outbound_conn = $profile[1]['outbound_conn']
    $disp_notification = $profile[1]['disp_notification']
    $allow_unicast = $profile[1]['allow_unicast']
    $local_firewall_rules = $profile[1]['local_firewall_rules']
    $local_security_rules = $profile[1]['local_security_rules']
    windows_firewall_profile { compliance::policy_title($item_id,$item_title,$setting_desc,$rule_title):
      name                       => $rule_title,
      filename                   => '%systemroot%\system32\logfiles\firewall\pfirewall.log',
      firewallpolicy             => "${inbound_conn},${outbound_conn}",
      inboundusernotification    => $disp_notification,
      localconsecrules           => $local_firewall_rules,
      localfirewallrules         => $local_security_rules,
      state                      => $firewall_state,
      unicastresponsetomulticast => $allow_unicast,
    }
  }
}
