define windows_cis::download (
  $url,
  $destination,
){
  validate_string( $url )
  validate_string( $destination )
  
  # Get filename from URL
  #
  $filearray    = split( $url, '/' )
  $filename     = $filearray[-1]

  # Ensure the destination directory with a File resource
  #
  if !defined( File["${destination}"] ) {
    @file { "${destination}":
      ensure    => directory,
    } 
  }
  realize( File["${destination}"] )
      
  # Divine for the appropriate command based on kernel
  #
  @exec { "download-${filename}":  
    command     => $::kernel ? {    
      windows   => "(New-Object System.Net.WebClient).DownloadFile('${url}', '${destination}\\${filename}')",
      linux     => "/usr/bin/curl ${url} -o ${destination}/${filename}",
    },
    provider    => $::kernel ? {
      'windows' => powershell,
      'linux'   => shell,
    },
    creates     => "${destination}/${filename}",
    require     => File["${destination}"],   
  }
  realize( Exec["download-${filename}"] )
}