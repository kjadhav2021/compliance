# @summary BNM compliance
#
# compliance baseline based on 'Secure Configuration Documents' SCD
#
# @example
#   include compliance
class compliance {
  case $facts['osfamily'] {
    'RedHat': {
      info('RHEL security baseline') # include bnm_compliance::rhel
    }
    'windows': {
      info('Windows security baseline')
      include compliance::windows
    }
    default: {
      fail('N/A - Security compliance standard is not implemented for this OS')
    }
  }
}
