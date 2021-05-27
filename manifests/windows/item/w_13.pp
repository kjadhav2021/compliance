# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_13
class compliance::windows::item::w_13 {

  # registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL2.0\
  # Client\DisabledByDefault':
  #   ensure => present,
  #   type   => dword,
  #   data   => 0x00000001,
  # }
  # registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL2.0\Server\Enabled':
  #   ensure => present,
  #   type   => dword,
  #   data   => 0x00000000,
  # }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL3.0\Client\
  DisabledByDefault':
    ensure => present,
    type   => dword,
    data   => 0x00000001,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL3.0\Server\Enabled':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  # registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS1.0\Server
  # \DisabledByDefault':
  #   ensure => present,
  #   type   => dword,
  #   data   => 0x00000001,
  # }
  # registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS1.0\Server\Enabled':
  #   ensure => present,
  #   type   => dword,
  #   data   => 0x00000000,
  # }
  # registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS1.1\Server
  # \DisabledByDefault':
  #   ensure => present,
  #   type   => dword,
  #   data   => 0x00000001,
  # }
  # registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS1.1\Server\Enabled':
  #   ensure => present,
  #   type   => dword,
  #   data   => 0x00000000,
  # }
  # registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS1.2\Server
  # \DisabledByDefault':
  #   ensure => present,
  #   type   => dword,
  #   data   => 0x00000000,
  # }
  # registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS1.2\Server\Enabled':
  #   ensure => present,
  #   type   => dword,
  #   data   => 0x00000001,
  # }
  # registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS1.2\Client
  # \DisabledByDefault':
  #   ensure => present,
  #   type   => dword,
  #   data   => 0x00000000,
  # }
  # registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS1.2\Client\Enabled':
  #   ensure => present,
  #   type   => dword,
  #   data   => 0x00000001,
  # }
  # registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\TripleDES168\Enabled':
  #   ensure => present,
  #   type   => dword,
  #   data   => 0x00000000,
  # }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128\Enabled':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128\Enabled':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128\Enabled':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  # registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS\Enabled':
  #   ensure => present,
  #   type   => dword,
  #   data   => 0x00000000,
  # }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\EnableSecuritySignature':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
}
