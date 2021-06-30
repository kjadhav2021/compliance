# @summary BNM compliance
#
# compliance baseline based on 'Secure Configuration Documents' SCD
#
# @example
#   include compliance
class compliance {
  case $facts['osfamily'] {
    'RedHat': {
      info('RHEL security basline')
      # include bnm_compliance::rhel
    }
    'windows': {
      info('Windows security basline')
      include compliance::windows
      # include compliance::windows::item::w_1
    }
    default: {
      warning('N/A - Security compliance standard is implemented for this OS')
    }
  }
}
