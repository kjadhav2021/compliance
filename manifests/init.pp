# @summary A short summary of the purpose of this class
#
# A description of what this class does
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
      # include compliance::windows
      # include compliance::windows::item::w_1
      include compliance::windows::item::w_2
      include compliance::windows::item::w_3
      include compliance::windows::item::w_4
    }
    default: {
      warning('N/A - Security compliance standard is implemented for this OS')
    }
  }
}
