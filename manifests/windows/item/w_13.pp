# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_13
class compliance::windows::item::w_13 (
  Boolean $report_only    = true,
  Hash    $policy_items     = { 'Accounts: Administrator account status' => {
                                  'policy_value' => '1'
                                },
                                'Accounts: Limit local account use of blank passwords to console logon only' => {
                                  'policy_value' => '1'
                                },
                                'Audit: Audit the access of global system objects' => {
                                  'policy_value' => '0'
                                },
                                'Audit: Audit the use of Backup and Restore privilege' => {
                                  'policy_value' => '0'
                                },
                                'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' => { # lint:ignore:140chars
                                  'policy_value' => '1'
                                },
                                'Audit: Shut down system immediately if unable to log security audits' => {
                                  'policy_value' => '0'
                                },
                                'Devices: Allow undock without having to log on' => {
                                  'policy_value' => '0'
                                },
                                # 0 - Administrators, 1 - Administrators and Power Users, 2 - Administrators and Interactive User
                                'Devices: Allowed to format and eject removable media' => {
                                  'policy_value' => '"0"'
                                },
                                'Devices: Prevent users from installing printer drivers' => {
                                  'policy_value' => '1'
                                },
                                'Domain controller: Allow server operators to schedule tasks' => {
                                  'domain_policy_value' => '0',
                                  'path'                => 'HKLM\System\CurrentControlSet\Control\LSA\SubmitControl',
                                  'type'                => 'dword'
                                },
                                'Domain controller: LDAP server signing requirements' => {
                                  'domain_policy_value' => '1',
                                  'path'                => 'HKLM\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity',
                                  'type'                => 'dword',
                                },
                                'Domain controller: Refuse machine account password changes' => {
                                  'domain_policy_value' => '0',
                                  'path'                => 'HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\RefusePasswordChange', # lint:ignore:140chars
                                  'type'                => 'dword',
                                },
                                'Domain member: Digitally encrypt secure channel data (when possible)' => {
                                  'policy_value' => '1'
                                },
                                'Domain member: Digitally sign secure channel data (when possible)' => {
                                  'policy_value' => '1'
                                },
                                'Domain member: Disable machine account password changes' => {
                                  'policy_value' => '0'
                                },
                                'Domain member: Maximum machine account password age' => {
                                  'policy_value' => '30'
                                },
                                'Domain member: Require strong (Windows 2000 or later) session key' => {
                                  'policy_value' => '1'
                                },
                                'Interactive logon: Do not display last user name' => {
                                  'policy_value' => '1'
                                },
                                'Interactive logon: Do not require CTRL+ALT+DEL' => {
                                  'policy_value' => '0'
                                },
                                'Interactive logon: Machine account lockout threshold' => {
                                  'policy_value' => '3'
                                },
                                'Interactive logon: Machine inactivity limit' => {
                                  'policy_value' => '900'
                                },
                                'Interactive logon: Message text for users attempting to log on' => {
                                  'policy_value' => 'WARNING: By accessing and using this system you are consenting to system monitoring for law enforcement and other purposes. Unauthorized use of this computer system may subject you to criminal prosecution and penalties.' # lint:ignore:140chars
                                },
                                'Interactive logon: Message title for users attempting to log on' => {
                                  'policy_value' => '"IT IS AN OFFENSE TO CONTINUE WITHOUT PROPER AUTHORIZATION"'
                                },
                                'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' => {
                                  'policy_value' => '"4"'
                                },
                                'Interactive logon: Prompt user to change password before expiration' => {
                                  'policy_value' => '14'
                                },
                                'Interactive logon: Require smart card' => {
                                  'policy_value' => '0'
                                },
                                'Interactive logon: Smart card removal behavior' => {
                                  'policy_value' => '"1"'
                                },
                                'Microsoft network client: Digitally sign communications (always)' => {
                                  'policy_value' => '1'
                                },
                                'Microsoft network client: Send unencrypted password to third-party SMB servers' => {
                                  'policy_value' => '0'
                                },
                                'Microsoft network server: Amount of idle time required before suspending session' => {
                                  'policy_value' => '15'
                                },
                                'Microsoft network server: Digitally sign communications (always)' => {
                                  'policy_value' => '1'
                                },
                                'Microsoft network server: Disconnect clients when logon hours expire' => {
                                  'policy_value' => '1'
                                },
                                'MSS: (AutoAdminLogon) Enable Automatic Logon(Not Recommended)' => {
                                  'policy_value' => ''
                                },
                                'Network access: Allow anonymous SID/name translation' => {
                                  'policy_value' => '0'
                                },
                                'Network access: Do not allow anonymous enumeration of SAM accounts' => {
                                  'policy_value' => '1'
                                },
                                'Network access: Do not allow anonymous enumeration of SAM accounts and shares' => {
                                  'policy_value' => '1'
                                },
                                'Network access: Let Everyone permissions apply to anonymous users' => {
                                  'policy_value' => '0'
                                },
                                'Network access: Remotely accessible registry paths' => {
                                  'policy_value' => [ 'System\\CurrentControlSet\\Control\\ProductOptions',
                                                      'System\\CurrentControlSet\\Control\\Server Applications',
                                                      'Software\\Microsoft\\Windows NT\\CurrentVersion',
                                                    ]
                                },
                                'Network access: Remotely accessible registry paths and sub-paths' => {
                                  'policy_value' => [ 'System\\CurrentControlSet\\Control\\Print\\Printers',
                                                      'System\\CurrentControlSet\\Services\\Eventlog',
                                                      'Software\\Microsoft\\OLAP Server',
                                                      'Software\\Microsoft\\Windows NT\\CurrentVersion\\Print',
                                                      'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows',
                                                      'System\\CurrentControlSet\\Control\\ContentIndex',
                                                      'System\\CurrentControlSet\\Control\\Terminal Server',
                                                      'System\\CurrentControlSet\\Control\\Terminal Server\\User Config',
                                                      'System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration',
                                                      'Software\\Microsoft\\Windows NT\\CurrentVersion\\perflib',
                                                      'System\\CurrentControlSet\\Services\\SysmonLog'
                                                    ]
                                },
                                'Network access: Restrict anonymous access to Named Pipes and Shares' => {
                                  'policy_value' => '1'
                                },
                                # 0 - Sharing and security model for local account - Classic - local users authenticate as themselves
                                'Network access: Sharing and security model for local accounts' => {
                                  'policy_value' => '0'
                                },
                                'Network security: All Local System to use computer identity for NTLM' => {
                                  'policy_value' => '1'
                                },
                                'Network security: Allow LocalSystem NULL session fallback' => {
                                  'policy_value' => '0'
                                },
                                'Network security: Do not store LAN Manager hash value on next password change' => {
                                  'policy_value' => '1'
                                },
                                'Network security: Force logoff when logon hours expire' => {
                                  'policy_value' => '1'
                                },
                                'Network security: LAN Manager authentication level' => {
                                  'policy_value' => '4'
                                },
                                'Network security: LDAP client signing requirements' => {
                                  'policy_value' => '1'
                                },
                                'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' => {
                                  'policy_value' => '4,537395200'
                                },
                                'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' => {
                                  'policy_value' => '4,537395200'
                                },
                                'Recovery console: Allow automatic administrative logon' => {
                                  'policy_value' => '0'
                                },
                                'Recovery console: Allow floppy copy and access to all drives and all folders' => {
                                  'policy_value' => '0'
                                },
                                'Shutdown: Allow system to be shut down without having to log on' => {
                                  'policy_value' => '0'
                                },
                                'Shutdown: Clear virtual memory pagefile' => {
                                  'policy_value' => '0'
                                },
                                'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' => {
                                  'policy_value' => '0'
                                },
                                'System objects: Require case insensitivity for non-Windows subsystems' => {
                                  'policy_value' => '1'
                                },
                                'System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)' => {
                                  'policy_value' => '1'
                                },
                                'System settings: Optional subsystems' => {
                                  'policy_value' => ' '
                                },
                                'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies' => {
                                  'policy_value' => '0'
                                },
                                'User Account Control: Admin Approval Mode for the Built-in Administrator account' => {
                                  'policy_value' => '1'
                                },
                                'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' => { # lint:ignore:140chars
                                  'policy_value' => '0'
                                },
                                'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' => {
                                  'policy_value' => '5'
                                },
                                'User Account Control: Behavior of the elevation prompt for standard users' => {
                                  'policy_value' => '3'
                                },
                                'User Account Control: Detect application installations and prompt for elevation' => {
                                  'policy_value' => '1'
                                },
                                'User Account Control: Only elevate executables that are signed and validated' => {
                                  'policy_value' => '0'
                                },
                                'User Account Control: Only elevate UIAccess applications that are installed in secure locations' => {
                                  'policy_value' => '1'
                                },
                                'User Account Control: Run all administrators in Admin Approval Mode' => {
                                  'policy_value' => '1'
                                },
                                'User Account Control: Switch to the secure desktop when prompting for elevation' => {
                                  'policy_value' => '1'
                                },
                                'User Account Control: Virtualize file and registry write failures to per-user locations' => {
                                  'policy_value' => '1'
                                }
                              }
) {
  # The below line sets this class and any contained classes/resources to noop/reporting mode
  if $report_only { noop() }

  Notify {
    tag       => ['compliance_rule'],
    loglevel  => 'debug'
  }

  $item_id      = 'w_13'
  $item_title   = 'Configure security options'

  # Below this line comes all Puppet code required to enforce the standard
  # ----------------------------------------------------------------------
  $policy_items.each |$k,$d| {
    $ensure = $d['policy_value']? { '' => 'absent', default => 'present' }
    if $d['domain_policy_value'] and str2bool($facts['windows_is_domain_controller']) {
      $value = $d['domain_policy_value']
    } elsif $d['policy_value'] {
      $value = $d['policy_value']
    } else {
      $value = undef
    }

    unless $value == undef {
      $setting_desc = $d['policy_value'] ? {
        ''      => '<Leave it blank>',
        '0'     => 'Disabled',
        '1'     => 'Enabled',
        default => 'Security options',
      }
      if $d['path'] {
        registry_value { bnm_compliance::policy_title($item_id, $k, $setting_desc, "${value} "):
          ensure => $ensure,
          path   => $d['path'],
          type   => $d['type'],
          data   => $value,
        }
      } else {
        $lsp_value = is_array($value)? { true => join($value,','), default => $value.strip }
        local_security_policy { bnm_compliance::policy_title($item_id, $k, $setting_desc, "${value} "):
          ensure       => $ensure,
          name         => $k,
          policy_value => $lsp_value
        }
      }
    }
  }
}
