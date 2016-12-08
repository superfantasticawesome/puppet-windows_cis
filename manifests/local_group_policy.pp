class windows_cis::local_group_policy {
  # Author's Note: See http://blogs.technet.com/b/secguide/archive/2016/01/21/lgpo-exe-local-group-policy-object-utility-v1-0.aspx
  #
  windows_cis::download { 'download-LGPO.zip':
    url         => 'http://blogs.technet.com/cfs-filesystemfile.ashx/__key/telligent-evolution-components-attachments/01-4062-00-00-03-65-94-11/LGPO.zip',
    destination => 'C:\Staging',
  }
  
  exec { 'unzip-LGPO.zip':
    command     => 'C:\ProgramData\chocolatey\tools\7za.exe x C:\Staging\LGPO.zip "-oC:\Staging\LGPO" -y',
    cwd         => 'C:\Staging',
    creates     => 'C:\Staging\LGPO\LGPO.exe',
  }
  
  # secedit /export /cfg c:\secpol.cfg
  # (Get-Content C:\secpol.cfg).Replace("PasswordComplexity = 1", "PasswordComplexity = 0") | Out-File C:\secpol.cfg
  # secedit /configure /db C:\Windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
  # Remove-Item -Force -Path c:\secpol.cfg -Confirm:$False
}