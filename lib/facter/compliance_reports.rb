# compliance run report
require 'facter'
require 'json'
require 'puppet'

# Puppet.initialize_settings
compliance_report = {}
compliance_fail_report = {}

# load classes with compliance item
def load_classfile_with_item
  if File.file?(Puppet['classfile'])
    (File.read(Puppet['classfile']).split("\n").select { |f| f.include?('compliance') && f.include?('::item::') }).sort
  else
    {}
  end
end

# read last run yaml report
def load_report(path)
  YAML.load_file(path)
end

# determine product_name
def load_produce_name(class_name)
  product_name = class_name.split('::')[1]
  if product_name == 'item'
    product_name = ''
  end
  product_name
end

# loading all corrective resources starting with "(" - both reportin and enforcement
# if require only retreive reporitng include '&& value.changed == false'
def resource_with_item(report)
  report.resource_statuses.select { |key, value| key.include?('[(') && value.out_of_sync == true }.keys
end

# determine pass/fail - single
def inspect_pass_fail(res, cp_key)
  (res.any? { |s| s =~ %r{#{cp_key}[_),]+} }) ? 'fail' : 'pass'
end

# determine pass/fail - group
def inspect_pass_fail_group(res, cp_key)
  (res.any? { |s| s =~ %r{#{cp_key[0]}[_),]+#{cp_key[1]}[_),]+} }) ? 'fail' : 'pass'
end

# Load classes file with items
class_item = load_classfile_with_item
unless class_item.empty?
  report = load_report(Puppet[:lastrunreport])
  compliance_res = resource_with_item(report)

  # setup report time
  compliance_report['report_time'] = report.time
  compliance_fail_report['report_time'] = report.time

  # skip reporting if last puppet is not unchanged status
  # TODO PE2017.3 - transaction_completed not found
  # if report.nil? || report.transaction_completed == false
  if report.nil?
    compliance_report['summary'] = 'inconclusive puppet run to determine compliance report, trigger puppet run'
    class_item = []
  end

  # item classes loop
  re = %r{[a-z0-9]+_[0-9]+}m
  class_item.each do |cf|
    cf_a = cf.scan(re)
    compliance_key = cf_a[0]

    # determine whether compliance item range pass or fail
    if cf_a.count == 1 # handle single compliance item
      compliance_report[compliance_key] = inspect_pass_fail(compliance_res, compliance_key)
      compliance_fail_report[compliance_key] = 'fail' if compliance_report[compliance_key] == 'fail'

    else # handle range compliance items by generate the id seperately
      (compliance_key.split('_', 2)[1].to_i...cf_a[1].split('_', 2)[1].to_i + 1).each do |cf_i|
        compliance_key = compliance_key.split('_', 2)[0] + '_' + cf_i.to_s

        # inspect each generate compliance item
        compliance_report[compliance_key] = inspect_pass_fail_group(compliance_res, cf_a)
        compliance_fail_report[compliance_key] = 'fail' if compliance_report[compliance_key] == 'fail'

        # already found fail resource skip the rest
        next unless compliance_report[compliance_key] == 'pass'
        # inspect pass fail on single classes
        compliance_report[compliance_key] = inspect_pass_fail(compliance_res, compliance_key)
        compliance_fail_report[compliance_key] = 'fail' if compliance_report[compliance_key] == 'fail'
      end
    end
  end
  compliance_report['overall_status'] = (compliance_report.any? { |s| s.include? 'fail' }) ? 'fail' : 'pass'
  compliance_report['compliance_last_reviewed'] = Facter.value(:compliance_last_reviewed) unless Facter.value(:compliance_last_reviewed).nil?
  compliance_report['compliance_reviewed_comment'] = Facter.value(:compliance_reviewed_comment) unless Facter.value(:compliance_reviewed_comment).nil?
  compliance_fail_report['compliance_last_reviewed'] = Facter.value(:compliance_last_reviewed) unless Facter.value(:compliance_last_reviewed).nil?
  compliance_fail_report['compliance_reviewed_comment'] = Facter.value(:compliance_reviewed_comment) unless Facter.value(:compliance_reviewed_comment).nil?
end

Facter.add('compliance_report') do
  setcode do
    compliance_report unless compliance_report.empty?
  end
end

Facter.add('compliance_report_fails') do
  setcode do
    compliance_fail_report unless compliance_fail_report.empty?
  end
end
