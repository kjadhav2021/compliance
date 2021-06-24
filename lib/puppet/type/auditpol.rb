# Puppet Type: auditpol
#
Puppet::Type.newtype(:auditpol) do
  @doc = 'Auditpol type for Windows'
  desc 'Auditpol type for Windows'

  newparam(:subcategory, namevar: true) do
    desc 'The subcategory of the policy.'
  end

  newproperty(:policy_value) do
    desc 'Audit Policy Setting Value'
    newvalues('Success,Failure', 'Success', 'Failure', 'No auditing')
    validate do |value|
      if value.nil? || value.empty?
        raise ArgumentError('Value cannot be nil or empty')
      end
    end
  end
end
