# Puppet Type provider: Auditpol
#
Puppet::Type.type(:auditpol).provide(:auditpol) do
  confine osfamily: :windows
  defaultfor osfamily: :windows

  commands auditpol: 'auditpol.exe'

  def initialize(value = {})
    super(value)
    @property_flush = {}
  end

  def policy_value
    @property_hash[:policy_value]
  end

  def policy_value=(value)
    @property_flush[:policy_value] = value
  end

  def flush
    options = []
    if @property_flush
      (options << '/set')
      (options << "/subcategory:#{resource[:subcategory]}")
      (options << '/success:' + ((resource[:policy_value].to_s.include? 'Success') ? 'enable' : 'disable'))
      (options << '/failure:' + ((resource[:policy_value].to_s.include? 'Failure') ? 'enable' : 'disable'))
    end
    auditpol(options) unless options.empty?
    @property_hash = resource.to_hash
  end

  def self.instances
    # generate a list of all categories and subcategories in csv
    categories = auditpol('/get', '/category:*', '/r')

    # the drop(1) drops the header line
    categories.split("\n").drop(1).map do |line|
      line_array = line.split(',')
      subcategory_name = line_array[2]
      subcategory_policy = line_array[4]

      policy_value = case subcategory_policy
                     when 'Success'
                       'Success'
                     when 'Failure'
                       'Failure'
                     when 'Success and Failure'
                       'Success,Failure'
                     when 'No Auditing'
                       'No auditing'
                     else # disable all if something weird happened I guess
                       'No auditing'
                     end

      new(name: subcategory_name,
          policy_value: policy_value)
    end
  end

  def self.prefetch(resources)
    policies = instances
    resources.each_key do |name|
      found_pol = policies.find { |pol| pol.name == name }
      resources[name].provider = found_pol if found_pol
    end
  end
end
