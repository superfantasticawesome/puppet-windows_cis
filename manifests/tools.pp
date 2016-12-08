# Install the Remote System Administration Tools (RSAT) and the GPMC
# https://technet.microsoft.com/en-us/library/cc730825.aspx
#
class windows_cis::tools {
  include windows_cis::powershell_profile
  
  if ( '2012' in $::operatingsystemrelease ) {
    $windows_feature = 'Install-WindowsFeature'
  } else {
    $windows_feature = 'Add-WindowsFeature'
  }
  
  $windows_feature = 'Add-WindowsFeature'
  case $::domain_role {
    'domain_controler': {
      exec { 'Install GPMC':
        command  => "Get-WindowsFeature –Name GPMC | ${windows_feature}",
        unless   => '@{$True=1; $False=0}[(Get-WindowsFeature -Name GPMC).installstate]',
        provider => powershell,
      }
    }
    'domain_controler','member_server': {
      exec { 'Install RSAT Tools':
        command  => "Get-WindowsFeature -Name RSAT-AD-PowerShell | ${windows_feature}",
        unless   => '@{$True=1; $False=0}[(Get-WindowsFeature -Name RSAT-AD-PowerShell).installstate]',
        provider => powershell,
      }
    }
    default: {
    }
  }
}