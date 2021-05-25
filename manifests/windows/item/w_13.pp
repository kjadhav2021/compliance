# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_13
class compliance::windows::item::w_13 {

  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\
  Client\DisabledByDefault':
    ensure => present,
    type   => dword,
    data   => 0x00000001,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server\Enabled':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client\
  DisabledByDefault':
    ensure => present,
    type   => dword,
    data   => 0x00000001,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server\Enabled':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server
  \DisabledByDefault':
    ensure => present,
    type   => dword,
    data   => 0x00000001,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\Enabled':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server
  \DisabledByDefault':
    ensure => present,
    type   => dword,
    data   => 0x00000001,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\Enabled':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server
  \DisabledByDefault':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\Enabled':
    ensure => present,
    type   => dword,
    data   => 0x00000001,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client
  \DisabledByDefault':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client\Enabled':
    ensure => present,
    type   => dword,
    data   => 0x00000001,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\TripleDES168\Enabled':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHA NNEL\Ciphers\RC4128\128\Enabled':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHA NNEL\Ciphers\RC440\128\Enabled':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHA NNEL\Ciphers\RC456\128\Enabled':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHA NNEL\KeyExchangeAlgorithms\PKCS\Enabled':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Param eters\EnableSecuritySignature\Enabled':
    ensure => present,
    type   => dword,
    data   => 0x00000000,
  }
  registry_value { 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Param eters\RequireSecuritySignature\Enabled':
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
