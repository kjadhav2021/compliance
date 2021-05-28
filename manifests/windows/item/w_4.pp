# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include compliance::windows::item::w_4
class compliance::windows::item::w_4 {
  class { 'archive':
    seven_zip_name     => '7-Zip 19.00 (x64 edition)',
    seven_zip_source   => 'https://www.7-zip.org/a/7z1900-x64.msi',
    seven_zip_provider => 'windows',
  }
}
