# frozen_string_literal: true

require 'puppet/provider'
require 'puppet/util'
require 'puppet/util/windows'

# class SecurityPolicy
class SecurityPolicy
  EVENT_TYPES = ['Success,Failure', 'Success', 'Failure', 'No auditing', 0, 1, 2, 3].freeze
  REGISTRY_TYPES = [1, 3, 4, 7].freeze

  def initialize; end

  def user_to_sid(value)
    if value.match?(%r{^\*})
      result = value
    else
      user_sid = Puppet::Util::Windows::SID.name_to_sid(value)
      if user_sid.nil?
        warn("\"#{value}\" does not exist")
      else
        result = '*' + user_sid
      end
    end
    result
  end

  # convert the sid to a user
  def sid_to_user(value)
    value = value.gsub(%r{(^\*)}, '')
    user = user_sid_array.find do |_home, _user, sid|
      value == sid
    end
    if user.nil?
      value
    else
      user[2]
    end
  end

  def convert_privilege_right(ensure_value, policy_value)
    # we need to convert users to sids first
    if ensure_value.to_s == 'absent'
      ''
    else
      sids = []
      policy_value.split(',').sort.each do |suser|
        suser.strip!
        cur_user_sid = user_to_sid(suser)
        sids << cur_user_sid unless cur_user_sid.nil?
      end
      sids.sort.join(',')
    end
  end

  # converts the policy value inside the policy hash to conform to the secedit standards
  def convert_policy_hash(policy_hash)
    value = case policy_hash[:policy_type]
            when 'Privilege Rights'
              convert_privilege_right(policy_hash[:ensure], policy_hash[:policy_value])
            when 'Event Audit'
              event_to_audit_id(policy_hash[:policy_value])
            when 'Registry Values'
              SecurityPolicy.convert_registry_value(policy_hash[:name], policy_hash[:policy_value])
            else
              policy_hash[:policy_value]
            end
    policy_hash[:policy_value] = value
    policy_hash
  end

  # Converts a event number to a word
  def self.event_audit_mapper(policy_value)
    case policy_value.to_s
    when 3
      'Success,Failure'
    when 2
      'Failure'
    when 1
      'Success'
    else
      'No auditing'
    end
  end

  # Converts a event number to a word
  def self.event_to_audit_id(event_audit_name)
    case event_audit_name
    when 'Success,Failure'
      3
    when 'Failure'
      2
    when 'Success'
      1
    when 'No auditing'
      0
    else
      event_audit_name
    end
  end

  # returns the key and hash value given the policy name
  def self.find_mapping_from_policy_name(name)
    key, value = lsp_mapping.find do |_key, hash|
      hash[:name] == name
    end
    unless key && value
      raise KeyError, "#{name} is not a valid policy"
    end
    [key, value]
  end

  # returns the key and hash value given the policy desc
  def self.find_mapping_from_policy_desc(desc)
    name = desc.downcase
    _key, value = lsp_mapping.find do |key, _hash|
      key.downcase == name
    end
    unless value
      raise KeyError, "#{desc} is not a valid policy"
    end
    value
  end

  def self.valid_lsp?(name)
    lsp_mapping.keys.include?(name)
  end

  def self.convert_registry_value(name, value)
    value = value.to_s
    return value if value.split(',').count > 1 && REGISTRY_TYPES.include?(value.split(',')[0].to_i)
    policy_hash = find_mapping_from_policy_desc(name)
    "#{policy_hash[:reg_type]},#{value}"
  end

  # converts the policy value to machine values
  def self.convert_policy_value(policy_hash, value)
    sp = SecurityPolicy.new
    # I would rather not have to look this info up, but the type code will not always have this info handy
    # without knowing the policy type we can't figure out what to convert
    policy_type = find_mapping_from_policy_desc(policy_hash[:name])[:policy_type]
    case policy_type.to_s
    when 'Privilege Rights'
      sp.convert_privilege_right(policy_hash[:ensure], value)
    when 'Event Audit'
      event_to_audit_id(value)
    when 'Registry Values'
      # convert the value to a datatype/value
      convert_registry_value(policy_hash[:name], value)
    else
      value
    end
  end

  def user_sid_array
    # need to cover local_accounts to name
    @user_sid_array ||= builtin_accounts
  end

  def builtin_accounts
    # more accounts and SIDs can be found at https://support.microsoft.com/en-us/kb/243330
    ary = [
      ['', 'NULL', 'S-1-0'],
      ['', 'NOBODY', 'S-1-0-0'],
      ['', 'EVERYONE', 'S-1-1-0'],
      ['', 'LOCAL', 'S-1-2-0'],
      ['', 'CONSOLE_LOGON', 'S-1-2-1'],
      ['', 'CREATOR_OWNER', 'S-1-3-0'],
      ['', 'CREATER_GROUP', 'S-1-3-1'],
      ['', 'OWNER_SERVER', 'S-1-3-2'],
      ['', 'GROUP_SERVER', 'S-1-3-3'],
      ['', 'OWNER_RIGHTS', 'S-1-3-4'],
      ['', 'NT_AUTHORITY', 'S-1-5'],
      ['', 'DIALUP', 'S-1-5-1'],
      ['', 'NETWORK', 'S-1-5-2'],
      ['', 'BATCH', 'S-1-5-3'],
      ['', 'INTERACTIVE', 'S-1-5-4'],
      ['', 'SERVICE', 'S-1-5-6'],
      ['', 'ANONYMOUS', 'S-1-5-7'],
      ['', 'PROXY', 'S-1-5-8'],
      ['', 'ENTERPRISE_DOMAIN_CONTROLLERS', 'S-1-5-9'],
      ['', 'PRINCIPAAL_SELF', 'S-1-5-10'],
      ['', 'AUTHENTICATED_USERS', 'S-1-5-11'],
      ['', 'RESTRICTED_CODE', 'S-1-5-12'],
      ['', 'TERMINAL_SERVER_USER', 'S-1-5-13'],
      ['', 'REMOTE_INTERACTIVE_LOGON', 'S-1-5-14'],
      ['', 'THIS_ORGANIZATION', 'S-1-5-15'],
      ['', 'IUSER', 'S-1-5-17'],
      ['', 'LOCAL_SYSTEM', 'S-1-5-18'],
      ['', 'LOCAL_SERVICE', 'S-1-5-19'],
      ['', 'NETWORK_SERVICE', 'S-1-5-20'],
      ['', 'COMPOUNDED_AUTHENTICATION', 'S-1-5-21-0-0-0-496'],
      ['', 'CLAIMS_VALID', 'S-1-5-21-0-0-0-497'],
      ['', 'BUILTIN_ADMINISTRATORS', 'S-1-5-32-544'],
      ['', 'BUILTIN_USERS', 'S-1-5-32-545'],
      ['', 'BUILTIN_GUESTS', 'S-1-5-32-546'],
      ['', 'POWER_USERS', 'S-1-5-32-547'],
      ['', 'ACCOUNT_OPERATORS', 'S-1-5-32-548'],
      ['', 'SERVER_OPERATORS', 'S-1-5-32-549'],
      ['', 'PRINTER_OPERATORS', 'S-1-5-32-550'],
      ['', 'BACKUP_OPERATORS', 'S-1-5-32-551'],
      ['', 'REPLICATOR', 'S-1-5-32-552'],
      ['', 'ALIAS_PREW2KCOMPACC', 'S-1-5-32-554'],
      ['', 'REMOTE_DESKTOP_USERS', 'S-1-5-32-555'],
      ['', 'NETWORK_CONFIGURATION_OPS', 'S-1-5-32-556'],
      ['', 'INCOMING_FOREST_TRUST_BUILDERS', 'S-1-5-32-557'],
      ['', 'PERMON_USERS', 'S-1-5-32-558'],
      ['', 'PERFLOG_USERS', 'S-1-5-32-559'],
      ['', 'WINDOWS_AUTHORIZATION_ACCESS_GROUP', 'S-1-5-32-560'],
      ['', 'TERMINAL_SERVER_LICENSE_SERVERS', 'S-1-5-32-561'],
      ['', 'DISTRIBUTED_COM_USERS', 'S-1-5-32-562'],
      ['', 'IIS_USERS', 'S-1-5-32-568'],
      ['', 'CRYPTOGRAPHIC_OPERATORS', 'S-1-5-32-569'],
      ['', 'EVENT_LOG_READERS', 'S-1-5-32-573'],
      ['', 'CERTIFICATE_SERVICE_DCOM_ACCESS', 'S-1-5-32-574'],
      ['', 'RDS_REMOTE_ACCESS_SERVERS', 'S-1-5-32-575'],
      ['', 'RDS_ENDPOINT_SERVERS', 'S-1-5-32-576'],
      ['', 'RDS_MANAGEMENT_SERVERS', 'S-1-5-32-577'],
      ['', 'HYPER_V_ADMINS', 'S-1-5-32-578'],
      ['', 'ACCESS_CONTROL_ASSISTANCE_OPS', 'S-1-5-32-579'],
      ['', 'REMOTE_MANAGEMENT_USERS', 'S-1-5-32-580'],
      ['', 'WRITE_RESTRICTED_CODE', 'S-1-5-32-558'],
      ['', 'NTLM_AUTHENTICATION', 'S-1-5-64-10'],
      ['', 'SCHANNEL_AUTHENTICATION', 'S-1-5-64-14'],
      ['', 'DIGEST_AUTHENTICATION', 'S-1-5-64-21'],
      ['', 'THIS_ORGANIZATION_CERTIFICATE', 'S-1-5-65-1'],
      ['', 'NT_SERVICE', 'S-1-5-80'],
      ['', 'NT_SERVICE\\ALL_SERVICES', 'S-1-5-80-0'],
      ['', 'NT_SERVICE\\WdiServiceHost', 'S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420'],
      ['', 'USER_MODE_DRIVERS', 'S-1-5-84-0-0-0-0-0'],
      ['', 'LOCAL_ACCOUNT', 'S-1-5-113'],
      ['', 'LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP', 'S-1-5-114'],
      ['', 'OTHER_ORGANIZATION', 'S-1-5-1000'],
      ['', 'ALL_APP_PACKAGES', 'S-1-15-2-1'],
      ['', 'ML_UNTRUSTED', 'S-1-16-0'],
      ['', 'ML_LOW', 'S-1-16-4096'],
      ['', 'ML_MEDIUM', 'S-1-16-8192'],
      ['', 'ML_MEDIUM_PLUS', 'S-1-16-8448'],
      ['', 'ML_HIGH', 'S-1-15-12288'],
      ['', 'ML_SYSTEM', 'S-1-16-16384'],
      ['', 'ML_PROTECTED_PROCESS', 'S-1-16-20480'],
      ['', 'AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY', 'S-1-18-1'],
      ['', 'SERVICE_ASSERTED_IDENTITY', 'S-1-18-2'],
      ['', 'WINDOWS_MANAGER\\WINDOWS_MANAGER_GROUP', 'S-1-5-90-0'],
    ]
    ary
  end

  def self.lsp_mapping
    @lsp_mapping ||= {
      # Password policy Mappings
      'Enforce password history' => {
        name: 'PasswordHistorySize',
        policy_type: 'System Access',
      },
      'Maximum password age' => {
        name: 'MaximumPasswordAge',
        policy_type: 'System Access',
      },
      'Minimum password age' => {
        name: 'MinimumPasswordAge',
        policy_type: 'System Access',
      },
      'Minimum password length' => {
        name: 'MinimumPasswordLength',
        policy_type: 'System Access',
      },
      'Password must meet complexity requirements' => {
        name: 'PasswordComplexity',
        policy_type: 'System Access',
      },
      'Store passwords using reversible encryption' => {
        name: 'ClearTextPassword',
        policy_type: 'System Access',
      },
      'Account lockout threshold' => {
        name: 'LockoutBadCount',
        policy_type: 'System Access',
      },
      'Account lockout duration' => {
        name: 'LockoutDuration',
        policy_type: 'System Access',
      },
      'Reset account lockout counter after' => {
        name: 'ResetLockoutCount',
        policy_type: 'System Access',
      },
      'Accounts: Rename administrator account' => {
        name: 'NewAdministratorName',
        policy_type: 'System Access',
        data_type: :quoted_string,
      },
      'Accounts: Administrator account status' => {
        name: 'EnableAdminAccount',
        policy_type: 'System Access',
      },
      'Accounts: Rename guest account' => {
        name: 'NewGuestName',
        policy_type: 'System Access',
        data_type: :quoted_string,
      },
      'Accounts: Require Login to Change Password' => {
        name: 'RequireLogonToChangePassword',
        policy_type: 'System Access',
      },
      'Network security: Force logoff when logon hours expire' => {
        name: 'ForceLogoffWhenHourExpire',
        policy_type: 'System Access',
      },
      'Network access: Allow anonymous SID/name translation' => {
        name: 'LSAAnonymousNameLookup',
        policy_type: 'System Access',
      },
      'EnableAdminAccount' => {
        name: 'EnableAdminAccount',
        policy_type: 'System Access',
      },
      'EnableGuestAccount' => {
        name: 'EnableGuestAccount',
        policy_type: 'System Access',
      },
      # Audit Policy Mappings
      'Audit account logon events' => {
        name: 'AuditAccountLogon',
        policy_type: 'Event Audit',
      },
      'Audit account management' => {
        name: 'AuditAccountManage',
        policy_type: 'Event Audit',
      },
      'Audit directory service access' => {
        name: 'AuditDSAccess',
        policy_type: 'Event Audit',
      },
      'Audit logon events' => {
        name: 'AuditLogonEvents',
        policy_type: 'Event Audit',
      },
      'Audit object access' => {
        name: 'AuditObjectAccess',
        policy_type: 'Event Audit',
      },
      'Audit policy change' => {
        name: 'AuditPolicyChange',
        policy_type: 'Event Audit',
      },
      'Audit privilege use' => {
        name: 'AuditPrivilegeUse',
        policy_type: 'Event Audit',
      },
      'Audit process tracking' => {
        name: 'AuditProcessTracking',
        policy_type: 'Event Audit',
      },
      'Audit system events' => {
        name: 'AuditSystemEvents',
        policy_type: 'Event Audit',
      },
      'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      # User rights mapping
      'Access Credential Manager as a trusted caller' => {
        name: 'SeTrustedCredManAccessPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Access this computer from the network' => {
        name: 'SeNetworkLogonRight',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Act as part of the operating system' => {
        name: 'SeTcbPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Add workstations to domain' => {
        name: 'SeMachineAccountPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Adjust memory quotas for a process' => {
        name: 'SeIncreaseQuotaPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Allow log on locally' => {
        name: 'SeInteractiveLogonRight',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Allow log on through Remote Desktop Services' => {
        name: 'SeRemoteInteractiveLogonRight',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Back up files and directories' => {
        name: 'SeBackupPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Bypass traverse checking' => {
        name: 'SeChangeNotifyPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Change the system time' => {
        name: 'SeSystemtimePrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Change the time zone' => {
        name: 'SeTimeZonePrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Create a pagefile' => {
        name: 'SeCreatePagefilePrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Create a token object' => {
        name: 'SeCreateTokenPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Create global objects' => {
        name: 'SeCreateGlobalPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Create permanent shared objects' => {
        name: 'SeCreatePermanentPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Create symbolic links' => {
        name: 'SeCreateSymbolicLinkPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Debug programs' => {
        name: 'SeDebugPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Deny access to this computer from the network' => {
        name: 'SeDenyNetworkLogonRight',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Deny log on as a batch job' => {
        name: 'SeDenyBatchLogonRight',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Deny log on as a service' => {
        name: 'SeDenyServiceLogonRight',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Deny log on locally' => {
        name: 'SeDenyInteractiveLogonRight',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Deny log on through Remote Desktop Services' => {
        name: 'SeDenyRemoteInteractiveLogonRight',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Enable computer and user accounts to be trusted for delegation' => {
        name: 'SeEnableDelegationPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Force shutdown from a remote system' => {
        name: 'SeRemoteShutdownPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Generate security audits' => {
        name: 'SeAuditPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Impersonate a client after authentication' => {
        name: 'SeImpersonatePrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Increase a process working set' => {
        name: 'SeIncreaseWorkingSetPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Increase scheduling priority' => {
        name: 'SeIncreaseBasePriorityPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Load and unload device drivers' => {
        name: 'SeLoadDriverPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Lock pages in memory' => {
        name: 'SeLockMemoryPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Log on as a batch job' => {
        name: 'SeBatchLogonRight',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Log on as a service' => {
        name: 'SeServiceLogonRight',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Manage auditing and security log' => {
        name: 'SeSecurityPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Modify an object label' => {
        name: 'SeRelabelPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Modify firmware environment values' => {
        name: 'SeSystemEnvironmentPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Perform volume maintenance tasks' => {
        name: 'SeManageVolumePrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Profile single process' => {
        name: 'SeProfileSingleProcessPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Profile system performance' => {
        name: 'SeSystemProfilePrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Remove computer from docking station' => {
        name: 'SeUndockPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Replace a process level token' => {
        name: 'SeAssignPrimaryTokenPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Restore files and directories' => {
        name: 'SeRestorePrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Shut down the system' => {
        name: 'SeShutdownPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Synchronize directory service data' => {
        name: 'SeSyncAgentPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      'Take ownership of files or other objects' => {
        name: 'SeTakeOwnershipPrivilege',
        policy_type: 'Privilege Rights',
        data_type: :principal,
      },
      # Registry Keys
      'Recovery console: Allow automatic administrative logon' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Recovery console: Allow floppy copy and access to all drives and all folders' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount',
        reg_type: '1',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Require Domain Controller authentication to unlock workstation' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Prompt user to change password before expiration' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Smart card removal behavior' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption',
        reg_type: '1',
        policy_type: 'Registry Values',
      },
      'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'User Account Control: Behavior of the elevation prompt for standard users' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Do not require CTRL+ALT+DEL' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Do not display last user name' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'User Account Control: Detect application installations and prompt for elevation' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'User Account Control: Run all administrators in Admin Approval Mode' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'User Account Control: Only elevate UIAccess applications that are installed in secure locations' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'User Account Control: Virtualize file and registry write failures to per-user locations' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'User Account Control: Admin Approval Mode for the Built-in Administrator account' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Message title for users attempting to log on' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption',
        reg_type: '1',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Message text for users attempting to log on' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText',
        reg_type: '7',
        policy_type: 'Registry Values',
      },
      'User Account Control: Switch to the secure desktop when prompting for elevation' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Require smart card' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Shutdown: Allow system to be shut down without having to log on' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Devices: Allow undock without having to log on' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'User Account Control: Only elevate executables that are signed and validated' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies' => {
        name: 'MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\AuthenticodeEnabled',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Audit: Audit the access of global system objects' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Audit: Shut down system immediately if unable to log security audits' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network access: Do not allow storage of passwords and credentials for network authentication' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network access: Let Everyone permissions apply to anonymous users' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network access: Sharing and security model for local accounts' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'System cryptography: Force strong key protection for user keys stored on the computer' => {
        name: 'MACHINE\Software\Policies\Microsoft\Cryptography\ForceKeyProtection',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Audit: Audit the use of Backup and Restore privilege' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing',
        reg_type: '3',
        policy_type: 'Registry Values',
      },
      'Accounts: Block Microsoft accounts' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Accounts: Limit local account use of blank passwords to console logon only' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network security: All Local System to use computer identity for NTLM' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network access: Remotely accessible registry paths' => {
        name: 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine',
        reg_type: '7',
        policy_type: 'Registry Values',
      },
      'Devices: Restrict CD-ROM access to locally logged-on user only' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateCDRoms',
        reg_type: '1',
        policy_type: 'Registry Values',
      },
      'Devices: Restrict floppy access to locally logged-on user only' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateFloppies',
        reg_type: '1',
        policy_type: 'Registry Values',
      },
      'Devices: Allowed to format and eject removable media' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD',
        reg_type: '1',
        policy_type: 'Registry Values',
      },
      'Devices: Prevent users from installing printer drivers' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Domain member: Digitally encrypt or sign secure channel data (always)' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Domain member: Digitally encrypt secure channel data (when possible)' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Domain member: Digitally sign secure channel data (when possible)' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Domain member: Disable machine account password changes' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Domain member: Maximum machine account password age' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Domain member: Require strong (Windows 2000 or later) session key' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Display user information when the session is locked' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLockedUserId',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Machine inactivity limit' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Machine account lockout threshold' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Microsoft network client: Digitally sign communications (always)' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Microsoft network client: Digitally sign communications (if server agrees)' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Microsoft network client: Send unencrypted password to third-party SMB servers' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Microsoft network server: Server SPN target name validation level' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\SmbServerNameHardeningLevel',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Microsoft network server: Amount of idle time required before suspending session' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Microsoft network server: Digitally sign communications (always)' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Microsoft network server: Digitally sign communications (if client agrees)' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Microsoft network server: Disconnect clients when logon hours expire' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network access: Named Pipes that can be accessed anonymously' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes',
        reg_type: '7',
        policy_type: 'Registry Values',
      },
      'Network access: Shares that can be accessed anonymously' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares',
        reg_type: '7',
        policy_type: 'Registry Values',
      },
      'Network access: Do not allow anonymous enumeration of SAM accounts and shares' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network access: Do not allow anonymous enumeration of SAM accounts' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network access: Remotely accessible registry paths and sub-paths' => {
        name: 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine',
        reg_type: '7',
        policy_type: 'Registry Values',
      },
      'Network access: Restrict anonymous access to Named Pipes and Shares' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network security: Do not store LAN Manager hash value on next password change' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network security: LAN Manager authentication level' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network security: LDAP client signing requirements' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'System objects: Require case insensitivity for non-Windows subsystems' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'System settings: Optional subsystems' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional',
        policy_type: 'Registry Values',
        reg_type: '7',
      },
      'Shutdown: Clear virtual memory pagefile' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax' => {
        name: 'MACHINE\Software\Policies\Microsoft\Windows NT\DCOM\MachineAccessRestriction',
        policy_type: 'Registry Values',
        reg_type: '1',
      },
      'DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax' => {
        name: 'MACHINE\Software\Policies\Microsoft\Windows NT\DCOM\MachineLaunchRestriction',
        policy_type: 'Registry Values',
        reg_type: '1',
      },
      'Microsoft network server: Attempt S4U2Self to obtain claim information' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableS4U2SelfForClaims',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Network access: Restrict clients allowed to make remote calls to SAM' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM',
        policy_type: 'Registry Values',
        reg_type: '1',
      },
      'Network security: Allow LocalSystem NULL session fallback' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Network security: Allow PKU2U authentication requests to this computer to use online identities' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\ClientAllowedNTLMServers',
        policy_type: 'Registry Values',
        reg_type: '7',
      },
      'Network security: Restrict NTLM: Add server exceptions in this domain' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DCAllowedNTLMServers',
        policy_type: 'Registry Values',
        reg_type: '7',
      },
      'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Network security: Restrict NTLM: Audit NTLM authentication in this domain' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\AuditNTLMInDomain',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Network security: Restrict NTLM: Incoming NTLM traffic' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictReceivingNTLMTraffic',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Network security: Restrict NTLM: NTLM authentication in this domain' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RestrictNTLMInDomain',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      "Interactive logon: Don't display last signed-in" => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      "Interactive logon: Don't display username at sign-in" => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayUserName',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Require Windows Hello for Business or smart card' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      ## Additional
      'Network security: Configure encryption types allowed for Kerberos' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'MSS: Allow IRDP to detect and configure Default gateway addresses' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'MSS: (TCPMaxDataRetransmissions) How many times unacknowledged data is retransmitted' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\TCPMaxDataRetransmissions',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'MSS: (TCPMaxDataRetransmissionsIPv6) How many times unacknowledged data is retransmitted' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters\TCPMaxDataRetransmissionsIPv6',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'MSS: (AutoAdminLogon) Enable Automatic Logon(Not Recommended)' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon',
        policy_type: 'Registry Values',
        reg_type: '1',
      },
      'MSS: (SafeDLLSearchMode) Enablesafe DLL search mode (Recommemded)' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode',
        policy_type: 'Registry Values',
        reg_type: '1',
      },
      'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Control Panel: Personalization: Prevent Enabling Lock Screen Camera' => {
        name: 'MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Control Panel: Personalization: Prevent Enabling Lock Screen Slide Show' => {
        name: 'MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'System: Early Launch Antimalware: Boot-Start Driver initialization Policy' => {
        name: 'MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'System: Group Policy: Configure Registry Policy Processing: Do Not Apply during Periodic Background Processing' => {
        name: 'MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'System: Group Policy: Configure Registry Policy Processing: Process Even if the Group Policy Objects Have not Changed' => {
        name: 'MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Internet Communication Management: Internet Communication Settings: Turn off Downloading of Print Driver over HTTP' => {
        name: 'MACHINE\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Internet Communication Management: Internet Communication Settings: Turn off Downloading for Web Publishing and Online Ordering Wizards' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Internet Communication Management: Internet Communication Settings: Turn off Printing over HTTP' => {
        name: 'MACHINE\Software\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Internet Communication Management: Internet Communication Settings: Turn off Search Companion Content File Updates' => {
        name: 'MACHINE\Software\Policies\Microsoft\SearchCompanion\DisableContentFileUpdates',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Internet Communication Management: Internet Communication Settings: Publish to Web Task for Files and Folders' => {
        name: 'MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoPublishingWizard',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Internet Communication Management: Internet Communication Settings: Turn off the Windows Messenger Customer Experience Improvement Program' => {
        name: 'MACHINE\Software\Policies\Microsoft\Messenger\Client\CEIP',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Logon: Do Not Display Network Selection UI' => {
        name: 'MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Remote Assistance: Configure Offer Remote Assistance' => {
        name: 'MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Remote Assistance:  Configure Solicited Remote Assistance' => {
        name: 'MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Remote Procedure Call: Enable RPC Endpoint Mapper Client Authentication' => {
        name: 'MACHINE\Software\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Windows Components: App Runtime Allow Microsoft Accounts to be Optional' => {
        name: 'MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Windows Components: AutoPlay Policies: turn off Autoplay' => {
        name: 'MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\NoDriveTypeAutoRun',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Maximum Application log size' => {
        name: 'MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Maximum security log size' => {
        name: 'MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Maximum System log size' => {
        name: 'MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Maximum Setup log size' => {
        name: 'MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\MaxSize',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Security: Control Event Log behaviour when the log file reaches its maximum size' => {
        name: 'MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security\Retention',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'System: Control Event Log behaviour when the log file reaches its maximum size' => {
        name: 'MACHINE\Software\Policies\Microsoft\Windows\EventLog\System\Retention',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Application: Control Event Log behaviour when the log file reaches its maximum size' => {
        name: 'MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application\Retention',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Restrict guest access to application log' => {
        name: 'MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application\Restrict-GuestAccess',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Restrict guest access to security log' => {
        name: 'MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security\Restrict-GuestAccess',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Restrict guest access to System log' => {
        name: 'MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System\Restrict-GuestAccess',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Domain: Firewall State' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Domain: Inbound Connection' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Domain: Outbound Connection' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Domain: Display Notification' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Domain: Allow Unicast Response' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableUnicastResponsesToMulticastBroadcast',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Domain: Apply Local Firewall Rules' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\AllowLocalPolicyMerge',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Domain: Apply Local Connection Security Rules' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\AllowLocalIPsecPolicyMerge',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Domain: Logging : Name to' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFilePath',
        policy_type: 'Registry Values',
        reg_type: '1',
      },
      'Domain: Logging : Size Limit' => {
        #:name => 'MACHINE\\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging\LogFileSize',
        name: 'MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Domain: Logging : Log Dropped Packets' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Domain: Logging : Log Successful Connections' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Private: Firewall State' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Private: Inbound Connections' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Private: Outbound Connections' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Private: Display a notification' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DisableNotifications',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Private: Allow Unicast Response' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DisableUnicastResponsesToMulticastBroadcast',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Private: Apply local Firewall Rules' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\AllowLocalPolicyMerge',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Private: Apply Local Connection Security Rules' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\AllowLocalIPsecPolicyMerge',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Private: Logging : Name to' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFilePath',
        policy_type: 'Registry Values',
        reg_type: '1',
      },
      'Private: Logging : Size limit(KB)' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Private: Logging : Log Dropped packets' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Private: Logging : Log Successful Connections' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Public: Firewall State' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Public: Inbound Connections' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Public: Outbound Connections' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Public: Display a notification' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DisableNotifications',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Public: Allow Unicast Response' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DisableUnicastResponsesToMulticastBroadcast',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Public: Apply local Firewall Rules' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Public: Apply Local Connection Security Rules' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Public: Logging : Name to' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFilePath',
        policy_type: 'Registry Values',
        reg_type: '1',
      },
      'Public: Logging : Size limit(KB)' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Public: Logging : Log Dropped packets' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'Public: Logging : Log Successful Connections' => {
        name: 'MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'MSS: (DisableIPSourceRouting) Disable IP Source routing' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
    }
  end
end
