# get_drive_type
def get_drive_type(arg)
  numperms = ['Unknown', 'NoRootDirectory', 'Removable', 'Fixed', 'Network', 'CDRom', 'Ram']
  numperms[arg]
end

# get_shares_accessright
def get_shares_accessright(arg)
  numperms = ['Full', 'Change', 'Read', 'Custom']
  numperms[arg]
end

# get_shares_accesscontroltype
def get_shares_accesscontroltype(arg)
  numperms = ['Allow', 'Deny']
  numperms[arg]
end

# get reg acl name
def get_reg_perm(arg)
  numperms = {
    1              => 'QueryValues',
    2              => 'SetValue',
    4              => 'CreateSubKey',
    8              => 'EnumerateSubKeys',
    16             => 'Notify',
    32             => 'CreateLink',
    131_097        => 'ReadKey',
    131_078        => 'WriteKey',
    65_536         => 'Delete',
    131_072        => 'ReadPermissions',
    262_144        => 'ChangePermissions',
    524_288        => 'TakeOwnership',
    983_103        => 'FullControl',
    268_435_456    => 'GENERIC_ALL',
    1_073_741_824  => 'GENERIC_WRITE',
    536_870_912    => 'GENERIC_EXECUTE',
    -2_147_483_648 => 'GENERIC_READ',
  }
  return numperms.key?(arg) ? numperms[arg] : arg if arg.is_a?(Integer)
  arg
end

# get reg acl name
def get_file_perm(arg)
  numperms = {
    1              => 'ListDirectory',
    2              => 'WriteData',
    4              => 'AppendData',
    8              => 'ReadExtendedAttributes',
    16             => 'WriteExtendedAttributes',
    32             => 'ExecuteFile',
    64             => 'DeleteSubdirectoriesAndFiles',
    256            => 'WriteAttributes',
    278            => 'Write',
    65_536         => 'Delete',
    131_072        => 'ReadPermissions',
    131_209        => 'read',
    131_241        => 'ReadAndExecute',
    197_055        => 'Modify',
    262_144        => 'ChangePermissions',
    524_288        => 'TakeOwnership',
    1_179_785      => 'read',
    1_179_817      => 'ReadAndExecute',
    1_180_063      => 'read, write',
    1_180_095      => 'ReadAndExecute, Write',
    1_245_631      => 'ReadAndExecute, Modify, Write',
    1_048_576      => 'Synchronize',
    2_032_127      => 'full',
    268_435_456    => 'FullControl (Sub Only)',
    -536_805_376   => 'Modify, Synchronize',
    -1_610_612_736 => 'ReadAndExecute, Synchronize',
  }

  return numperms.key?(arg) ? numperms[arg] : arg if arg.is_a?(Integer)
  arg
end

# preapre windows registry acl
def win_acl(args = {})
  if args[:reg_key]
    key = args[:reg_key]
    col_key = 'IdentityReference'
    col     = 'RegistryRights'
    win_col = 'RegistryRights'
  elsif args[:file] # both directory and file handling same
    key = args[:file]
    col_key = 'identity'
    col     = 'rights'
    win_col = 'FileSystemRights'
  else
    raise("invalid param - #{args}")
  end
  col_audit = args[:audit].nil? ? '' : ',AuditFlags'

  powershellcmd = "#{ENV['windir']}/system32/WindowsPowershell/v1.0/powershell.exe"
  object_field = args[:audit].nil? ? '.access' : '.audit'
  where_object = args[:where].nil? ? '' : "| Where-object #{args[:where]} "
  aclcmd = "(Get-Acl -Audit -Path '#{key}')#{object_field} #{where_object}| Select -Unique IdentityReference,#{win_col}#{col_audit} | ConvertTo-Json"

  raw_acl = Facter::Core::Execution.execute("#{powershellcmd} \"#{aclcmd} \" ")
  acl_item = raw_acl.empty? ? [] : JSON.parse(raw_acl)
  acl_item = acl_item.is_a?(Hash) ? [acl_item] : acl_item
  acl = []
  acl_item.each do |m|
    rights_val = if win_col == 'RegistryRights' then get_reg_perm(m[win_col])
                 elsif win_col == 'FileSystemRights' then [get_file_perm(m[win_col])]
                 else
                   m[win_col]
                 end
    acl << if args[:audit].nil?
             { col_key => (m['IdentityReference'])['Value'], col => rights_val }
           else
             { col_key => (m['IdentityReference'])['Value'], col => rights_val, 'AuditFlags' => m['AuditFlags'] }
           end
  end
  acl
end
