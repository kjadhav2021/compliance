# compliance::windows::item::w_21
#
# **Title:** Enforce strong/proper configuration of Windows Firewall Policy/Rule (if enabled) [Optional]
#
# **Description:** Windows Firewall helps protect the server by preventing unauthorized users from gaining access
# to the server through the Internet or a network. It can also stop types of malicious software that use network
# traffic to spread themselves, like Trojan horse attacks and worms. Another useful capability is that it can filter
# both outgoing and incoming connections and block those which are unwanted.
#
# **Impact:** Unauthorized access and spread of malicious software.
#
# **Risk Rating:** High
#
# **Standard Setting:** 1. Open the Server manager from the task bar.
# 2. On the right-hand side in the top navigation bar, click Tools and select Windows
# Firewall with Advanced Security.
# 3. ReviewthecurrentconfigurationsettingsbyselectingWindowsFirewallProperties from the Windows
# Firewall Microsoft Management Console (MMC) landing page. Access and modify the setting for each of the
# three firewall profiles, Domain, Private, and Public, as well as IPSec setting.
# **Note:** Screen saver password is required for servers located outside from Data Centre.
#
#
# @param report_only Whether or not to set the resources to noop mode
# @param firewall_rules firewall rules map
class compliance::windows::item::w_21 (
  Boolean $report_only = true,
  Hash $firewall_rules = { 'domain_profile'  => [ {'firewall_state' => 'on'},
{'inbound_conn' => 'blockinbound'},{'outbound_conn' => 'allowoutbound'},{'disp_notification' => 'enable'},
{'allow_unicast' => 'disable'},{'local_firewall_rules' => 'n/a (gpo-store only)'},{'local_security_rules' => 'n/a (gpo-store only)'} ],
'private_profile'  => [ {'firewall_state' => 'on'},{'inbound_conn' => 'blockinbound'},{'outbound_conn' => 'allowoutbound'},
{'disp_notification' => 'enable'},{'allow_unicast' => 'disable'},{'local_firewall_rules' => 'n/a (gpo-store only)'},
{'local_security_rules' => 'n/a (gpo-store only)'} ],
'public_profile'  => [ {'firewall_state' => 'on'},{'inbound_conn' => 'blockinbound'},{'outbound_conn' => 'allowoutbound'},
{'disp_notification' => 'enable'},{'allow_unicast' => 'disable'},{'local_firewall_rules' => 'n/a (gpo-store only)'},
{'local_security_rules' => 'n/a (gpo-store only)'} ],},
) {
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug',
  }

  $item_id      = 'w_21'
  $item_title   = 'Enforce strong/proper configuration of Windows Firewall Policy'
  $setting_desc = 'Enforce strong/proper configuration of Windows Firewall Policy'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  # $firewall_rules = lookup('compliance::windows::item::w_21::firewall_rules')
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
      # localconsecrules           => $local_firewall_rules,
      # localfirewallrules         => $local_security_rules,
      state                      => $firewall_state,
      unicastresponsetomulticast => $allow_unicast,
    }
  }
}
