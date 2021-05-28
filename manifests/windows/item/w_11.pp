# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_11
class compliance::windows::item::w_11 {
  # Audit and logging
  local_security_policy { 'Audit account logon events':
    ensure       => present,
    policy_value => 'Failure',
  }
  local_security_policy { 'Audit account management':
    ensure       => present,
    policy_value => 'Success,Failure',
  }
  local_security_policy { 'Audit directory service access':
    ensure       => present,
    policy_value => 'Success,Failure',
  }
  local_security_policy { 'Synchronize directory service data':
    ensure       => present,
    policy_value => 'Success,Failure',
  }

  local_security_policy { 'Audit logon events':
    ensure       => present,
    policy_value => 'Success,Failure',
  }
  local_security_policy { 'Audit policy change':
    ensure       => present,
    policy_value => 'Success,Failure',
  }
  local_security_policy { 'Audit privilege use':
    ensure       => present,
    policy_value => 'Success,Failure',
  }
  local_security_policy { 'Synchronize directory service data':
    ensure       => present,
    policy_value => 'Success,Failure',
  }


}
