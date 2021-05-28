# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_9
class compliance::windows::item::w_9 {
  # Password policy
  local_security_policy { 'Enforce password history':
    ensure       => present,
    policy_value => '24',
  }
  local_security_policy { 'Maximum password age':
    ensure       => present,
    policy_value => '60',
  }
  local_security_policy { 'Minimum password age':
    ensure       => present,
    policy_value => '1',
  }
  local_security_policy { 'Minimum Password Length':
    ensure       => present,
    policy_value => '14',
  }
  local_security_policy { 'Password must meet complexity requirements':
    ensure       => present,
    policy_value => 'Enabled',
  }
  local_security_policy { 'Store passwords using reversible encryption':
    ensure       => present,
    policy_value => 'Disabled',
  }
  # Account Lockout policy
  local_security_policy { 'Account lockout duration':
    ensure       => present,
    policy_value => '30',
  }
  local_security_policy { 'Account lockout threshold':
    ensure       => present,
    policy_value => '50',
  }
  local_security_policy { 'Reset account lockout counter after':
    ensure       => present,
    policy_value => '15',
  }
}
