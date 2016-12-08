# Install Carbon
# Carbon is a PowerShell module for automating the configuration of computers running Windows 7, 8, 2008, and 2012
# See: http://get-carbon.org/
# Download: https://bitbucket.org/splatteredbits/carbon/downloads
#
class windows_cis::carbon {
  $carbon_version      = '2.1.1'
  
  windows_cis::download { 'download-Carbon':
    url                => "https://bitbucket.org/splatteredbits/carbon/downloads/Carbon-${carbon_version}.zip",
    destination        => 'C:\Staging',
  }
  
  exec { 'unzip-Carbon':
    command            => "C:\\ProgramData\\chocolatey\\tools\\7za.exe x C:\\Staging\\Carbon-${carbon_version}.zip \"-oC:\\Staging\\Carbon\" -y",
    cwd                => 'C:\Staging',
    creates            => 'C:\Staging\Carbon\Carbon\Import-Carbon.ps1',
    require            => Windows_cis::Download['download-Carbon'],
  }
  
  file { 'C:\Program Files\WindowsPowerShell\Modules\Carbon':
    ensure             => directory,
    recurse            => true,
    backup             => false,
    source_permissions => ignore,
    source             => 'C:\Staging\Carbon\Carbon',
    require            => Exec['unzip-Carbon'],
  }
}