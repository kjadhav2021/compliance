# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_8
class compliance::windows::item::w_8 {
  service { 'ALG':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'AppMgmt':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'BITS':
    enable   => 'true',
    provider => 'windows',
  }
  service { 'EventSystem':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'COMSysApp':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'CryptSvc':
    ensure   => 'running',
    enable   => 'true',
    provider => 'windows',
  }
  service { 'TrkWks':
    ensure   => 'stopped',
    enable   => 'false',
    provider => 'windows',
  }
  service { 'MSDTC':
    ensure   => 'stopped',
    enable   => 'false',
    provider => 'windows',
  }
  service { 'SharedAccess':
    ensure   => 'stopped',
    enable   => 'false',
    provider => 'windows',
  }
  service { 'PolicyAgent':
    ensure   => 'running',
    enable   => 'true',
    provider => 'windows',
  }
  service { 'swprv':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'Netman':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'NlaSvc':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'WPDBusEnum':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'Power':
    enable   => 'true',
    provider => 'windows',
  }
  service { 'SessionEnv':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'TermService':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'UmRdpService':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'RpcSs':
    ensure   => 'running',
    enable   => 'true',
    provider => 'windows',
  }
  service { 'RpcLocator':
    ensure   => 'running',
    enable   => 'true',
    provider => 'windows',
  }
  service { 'RemoteRegistry':
    ensure   => 'running',
    enable   => 'true',
    provider => 'windows',
  }
  service { 'RSoPProv':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'RemoteAccess':
    ensure   => 'stopped',
    enable   => 'false',
    provider => 'windows',
  }
  service { 'seclogon':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'SamSs':
    ensure   => 'running',
    enable   => 'true',
    provider => 'windows',
  }
  service { 'LanmanServer':
    ensure   => 'running',
    enable   => 'true',
    provider => 'windows',
  }
  service { 'ShellHWDetection':
    ensure   => 'running',
    enable   => 'true',
    provider => 'windows',
  }
  service { 'SCardSvr':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'SCPolicySvc':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'sacsvr':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'lmhosts':
    enable   => 'true',
    provider => 'windows',
  }

  service { 'Themes':
    ensure   => 'stopped',
    enable   => 'false',
    provider => 'windows',
  }
  service { 'lmhosts':
    ensure   => 'stopped',
    enable   => 'false',
    provider => 'windows',
  }
  service { 'vds':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'Audiosrv':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'WerSvc':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'EventLog':
    enable   => 'true',
    provider => 'windows',
  }
  service { 'msiserver':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'Winmgmt':
    enable   => 'true',
    provider => 'windows',
  }
  service { 'W32Time':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'wuauserv':
    enable   => 'true',
    provider => 'windows',
  }
  service { 'WinHttpAutoProxySvc':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'wmiApSrv':
    enable   => 'manual',
    provider => 'windows',
  }
  service { 'LanmanWorkstation':
    enable   => 'true',
    provider => 'windows',
  }
}
