# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_12
class compliance::windows::item::w_12 (
  Boolean $report_only      = true,
  Hash    $policy_items     = { 'Access Credential Manager as a trusted caller' => {
                                  'policy_value' => ''
                                },
                                'Access this computer from the network' => {
                                  'policy_value' => [ 'Administrators',
                                                      'Authenticated Users' ],
                                  'domain_policy_value' =>  [ 'Administrators',
                                                              'Authenticated Users',
                                                              'ENTERPRISE DOMAIN CONTROLLERS' ]
                                },
                                'Act as part of the operating system' => {
                                  'policy_value' => ''
                                },
                                'Adjust memory quotas for a process' => {
                                  'policy_value' => [ 'LOCAL SERVICE',
                                                      'NETWORK SERVICE',
                                                      'Administrators' ]
                                },
                                'Allow log on locally' => {
                                  'policy_value' => [ 'Administrators' ]
                                },
                                'Allow log on through Remote Desktop Services' => {
                                  'policy_value' => [ 'Administrators' ]
                                },
                                'Back up files and directories' => {
                                  'policy_value' => [ 'Administrators',
                                                      'Backup Operators' ]
                                },
                                'Bypass traverse checking' => {
                                  'policy_value' => [
                                                      'Administrators',
                                                      'Authenticated Users',
                                                      'Local Service',
                                                      'Network Service',
                                                      'Backup Operators',
                                                      'Window Manager\Window Manager Group'
                                                    ],
                                },
                                'Change the system time' => {
                                  'policy_value' => [ 'LOCAL SERVICE',
                                                      'Administrators' ]
                                },
                                'Change the time zone' => {
                                  'policy_value' => [ 'LOCAL SERVICE',
                                                      'Administrators' ]
                                },
                                'Create a pagefile' => {
                                  'policy_value' => [ 'Administrators' ]
                                },
                                'Create a token object' => {
                                  'policy_value' => ''
                                },
                                'Create global objects' => {
                                  'policy_value' => [ 'Administrators',
                                                      'SERVICE',
                                                      'Local Service',
                                                      'Network Service',
                                                    ]
                                },
                                'Create permanent shared objects' => {
                                  'policy_value' => ''
                                },
                                'Create symbolic links' => {
                                  'policy_value' => [ 'Administrators' ]
                                },
                                'Debug programs' => {
                                  'policy_value' => [ 'Administrators' ]
                                },
                                'Deny access to this computer from the network' => {
                                  'policy_value' => [ 'Guests' ]
                                },
                                'Deny log on as a batch job' => {
                                  'policy_value' => [ 'Guests' ]
                                },
                                'Deny log on as a service' => {
                                  'policy_value' => [ 'Guests' ]
                                },
                                'Deny log on locally' => {
                                  'policy_value' => [ 'Guests' ]
                                },
                                'Deny log on through Remote Desktop Services' => {
                                  'policy_value' => [ 'Guests' ]
                                },
                                'Enable computer and user accounts to be trusted for delegation' => {
                                  'policy_value' => ''
                                },
                                'Force shutdown from a remote system' => {
                                  'policy_value' => [ 'Administrators' ]
                                },
                                'Generate security audits' => {
                                  'policy_value' => [ 'LOCAL SERVICE',
                                                      'NETWORK SERVICE' ]
                                },
                                'Impersonate a client after authentication' => {
                                  'policy_value' => [ 'Administrators',
                                                      'SERVICE',
                                                      'LOCAL SERVICE',
                                                      'NETWORK SERVICE',
                                                    ]
                                },
                                'Increase scheduling priority' => {
                                  'policy_value' => [ 'Administrators' ]
                                },
                                'Load and unload device drivers' => {
                                  'policy_value' => [ 'Administrators' ]
                                },
                                'Lock pages in memory' => {
                                  'policy_value' => [ 'Administrators' ]
                                },
                                'Manage auditing and security log' => {
                                  'policy_value' => [ 'Administrators' ]
                                },
                                'Modify an object label' => {
                                  'policy_value' => ''
                                },
                                'Modify firmware environment values' => {
                                  'policy_value' => [ 'Administrators' ]
                                },
                                'Perform volume maintenance tasks' => {
                                  'policy_value' => [ 'Administrators' ]
                                },
                                'Profile single process' => {
                                  'policy_value' => [ 'Administrators' ]
                                },
                                'Profile system performance' => {
                                  'policy_value' => [ 'Administrators',
                                                      'NT Service\WdiServiceHost' ]
                                },
                                'Replace a process level token' => {
                                  'policy_value' => [ 'LOCAL SERVICE',
                                                      'NETWORK SERVICE' ]
                                },
                                'Remove computer from docking station' => {
                                  'policy_value' => [ 'Administrators' ]
                                },
                                'Restore files and directories' => {
                                  'policy_value' => [ 'Administrators',
                                                      'Backup Operators' ]
                                },
                                'Shut down the system' => {
                                  'policy_value' => [ 'Administrators',
                                                      'Backup Operators' ]
                                },
                                'Synchronize directory service data' => {
                                  'policy_value' => ''
                                },
                                'Take ownership of files or other objects' => {
                                  'policy_value' => [ 'Administrators' ]
                                }
                              }
) {
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_12'
  $item_title   = 'Configure user rights'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  $policy_items.each |$k,$d| {
    $ensure = $d['policy_value']? { '' => 'absent', default => 'present' }
    if $d['domain_policy_value'] and str2bool($facts['windows_is_domain_controller']) {
      $value = $d['domain_policy_value']
    } else {
      $value = $d['policy_value']
    }
    $setting_desc = $d['policy_value'] ? {
      ''      => '<Leave it blank>',
      '0'     => 'Disabled',
      '1'     => 'Enabled',
      default => 'User rights',
    }
    $lsp_value = is_array($value)? { true => join($value,','), default => $value }
    local_security_policy { compliance::policy_title($item_id, $k, $setting_desc, "${value} "):
      ensure       => $ensure,
      name         => $k,
      policy_value => $lsp_value
    }
  }
}
