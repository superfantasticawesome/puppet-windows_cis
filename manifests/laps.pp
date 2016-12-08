# A class to manage the installation and configuration of the
# Microsoft Local Admin Password Solution
# See: https://technet.microsoft.com/en-us/library/security/3062591.aspx
#
class windows_cis::laps {
  include windows_cis::group_policy
  include windows_cis::gpupdate
  
  # CIS: 18.2 LAPS
  # This section contains recommendations for configuring the 
  # Microsoft Local Administrator Password Solution (LAPS).
  #
  
  case $::domain_role {
    # CIS: 18.2.1 (L1) Ensure LAPS AdmPwd GPO Extension / CSE is installed (MS only) (Scored)
    #
    'domain_controller','member_server': {  
      # Download the Local Administrator Password Solution (LAPS) from microsoft.com
      #
      windows_cis::download { 'download-LAPS.x64':
        url            => 'https://download.microsoft.com/download/C/7/A/C7AAD914-A8A6-4904-88A1-29E657445D03/LAPS.x64.msi',
        destination    => 'C:\Staging', 
      }

      # Configure the LAPS installer for role-appropriate features
      #
      case $::domain_role {
        'domain_controller': { $addlocal = 'ALL' }
        'member_server': { $addlocal = 'CSE' }
        default: {}
      }
  
      # Install LAPS.x64 with role-appropriate features using msiexec
      #
      exec { 'install-LAPS.x64':
        command        => "msiexec /i C:\\Staging\\LAPS.x64.msi ADDLOCAL=${addlocal} /quiet /norestart",
        path           => $::path,
        creates        => 'C:\Program Files\LAPS\CSE\AdmPwd.dll',
        require        => Windows_cis::Download['download-LAPS.x64'],
      } 
    }
    default: {
    }   
  }
  
  case $::domain_role {
    'domain_controller': {
      $dn_components   = split($::domain, '[.]')
      $dc_top_level    = $dn_components[-1]
      $dc_domain       = $dn_components[-2]
      
      # Update the Active Directory Schema
      #
      exec { 'Update-AdmPwdADSchema':
        command        => 'Import-Module AdmPwd.ps; Update-AdmPwdADSchema',
        unless         => 'Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter { CN -Like "ms-Mcs-AdmPwd" } | Select-Object -Expand Name  | Findstr /c:ms-Mcs-AdmPwd',
        provider       => powershell,
        require        => Exec['install-LAPS.x64'],
      }
      
      # Check/Set Computer Permissions to Read Local Admin Passwords
      #
      exec { 'Set-AdmPwdComputerSelfPermissions':
        command        => "Import-Module AdmPwd.ps; Set-AdmPwdComputerSelfPermission -OrgUnit 'OU=Domain Computers,DC=$dc_domain,DC=$dc_top_level'",
        unless         => "Import-Module AdmPwd.ps; Set-AdmPwdComputerSelfPermission -OrgUnit 'OU=Domain Computers,DC=$dc_domain,DC=$dc_top_level' | Select-Object -Expand Status | findstr /c:Delegated",
        provider       => powershell,
        require        => Exec['Update-AdmPwdADSchema'], 
      }  
      
      # Check/Set User Permissions to Read Local Admin Passwords
      #      
      exec { 'Set-AdmPwdReadPasswordfPermission':
        command        => "Import-Module AdmPwd.ps; Set-AdmPwdReadPasswordfPermission -OrgUnit 'OU=Domain Computers,DC=$dc_domain,DC=$dc_top_level' -AllowedPrincipals 'Domain Admins'",
        unless         => "Import-Module AdmPwd.ps; Find-AdmPwdExtendedRights -Identity 'OU=Domain Computers,DC=$dc_domain,DC=$dc_top_level' | findstr /c:'Domain Admins'",
        provider       => powershell,
        require        => Exec['Set-AdmPwdComputerSelfPermissions'],
      } 
      
      # Apply LAPS-related scored CIS benchmarks to the appropriate Domain Policy
      #
      $gpo_settings = {
        # CIS: 18.2.4 (L1) Set 'Password Settings: Password Complexity' to 
        # 'Enabled: Large letters + small letters + numbers + special characters' (MS only) (Scored)
        #
        'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd:PasswordComplexity' => {
          group_policies => [ 'CIS Domain Policy' ],
          registry_type  => 'dword',          
          registry_value => 4,
        },

        # CIS: 18.2.5 (L1) Set 'Password Settings: Password Length' to 'Enabled: 15 or more' (MS only) (Scored)
        #
        'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd:PasswordLength' => {
          group_policies => [ 'CIS Domain Policy' ],          
          registry_type  => 'dword',           
          registry_value => 15,
        },   
        
        # CIS: 18.2.6 (L1) Set 'Password Settings: Password Age (Days)' to 
        # 'Enabled: 30 or fewer' (MS only) (Scored)
        #
        'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd:PasswordAgeDays' => {
          group_policies => [ 'CIS Domain Policy' ],          
          registry_type  => 'dword',           
          registry_value => 30,
        }, 

        # CIS: 18.2.2 (L1) Set 'Do not allow password expiration time longer than required by policy' 
        # to 'Enabled' (MS only) (Scored)
        #
        'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd:PwdExpirationProtectionEnabled' => {
          group_policies => [ 'CIS Domain Policy' ],          
          registry_type  => 'dword',           
          registry_value => 1,
        }, 

        # CIS: 18.2.3 (L1) Set 'Enable Local Admin Password Management' to 
        # 'Enabled' (MS only) (Scored)
        #        
        'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd:AdmPwdEnabled' => {
          group_policies => [ 'CIS Domain Policy' ],
          registry_type  => 'dword',           
          registry_value => 1,
        }
      }
      create_resources(windows_cis::group_policy::setting, $gpo_settings) 
    }
    default: {
    }
  }
}