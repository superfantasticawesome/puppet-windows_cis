class windows_cis::powershell_profile {
  case $::domain_role {
    'domain_controller', 'member_server': {
      file { 'C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1':
        ensure             => present,
        source             => 'C:\Windows\System32\WindowsPowerShell\v1.0\Examples\profile.ps1',
        source_permissions => ignore,
      }
  
      file_line { 'Import-Module':
        ensure            => present,
        path              => 'C:/Windows/System32/WindowsPowerShell/v1.0/profile.ps1',
        line              => "Import-Module GroupPolicy\nImport-Module ActiveDirectory",
        require           => File['C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1'],
      }
    }
    default: {
    }    
  }
}