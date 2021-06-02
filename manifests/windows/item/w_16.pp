# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_16
class compliance::windows::item::w_16 (
  Boolean $report_only      = true,
  Hash    $directories_acl  = {
                                $facts['windows_env']['WINDIR'] => [
                                  { 'identity' => 'CREATOR OWNER', 'rights' => [ 'full' ] },
                                  { 'identity' => 'NT AUTHORITY\\SYSTEM', 'rights' => [ 'full' ] },
                                  { 'identity' => 'BUILTIN\\Administrators', 'rights' => [ 'full' ] },
                                  { 'identity' => 'BUILTIN\\Users', 'rights' => [ 'read', 'execute' ] } ],
                                "${facts['system32']}/LogFiles" =>  [
                                  {'rights' => ['read'], 'identity' => 'Everyone' },
                                  {'rights' => ['full'], 'identity' => 'NT AUTHORITY\\SYSTEM' },
                                  {'rights' => ['full'], 'identity' => 'BUILTIN\\Administrators' } ]
                              }
) {
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_16'
  $item_title   = 'Secure the permissions to critical system files'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  $directories_acl.each |$k, $d| {
    $setting_desc = "${k} shares"
    acl { compliance::policy_title($item_id, $item_title, $setting_desc, "${k}-${d}"):
      name                       => $k,
      inherit_parent_permissions => false,
      permissions                => $d,
      purge                      => true,
    }
  }
}
