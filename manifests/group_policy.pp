# This class and its attendant resources create group policy objects and
# links them to their domain-appropriate Organizational Units. This class also 
# configures group policy settings based on the corresponding group 
# policy/registry key. 
#
class windows_cis::group_policy {
  include windows_cis::tools
  include windows_cis::gpupdate
  include windows_cis::powershell_profile

  case $::domain_role {
    'domain_controller': {
      $gpos = {
        'CIS Domain Policy' => { 
          comment => 'Policy derived from the CIS MS Windows Server 2012 R2 Benchmark v2.1.0', 
          ou      => 'Domain Computers',
        },
        'CIS Domain Controller Policy' => { 
          comment => 'Policy derived from the CIS MS Windows Server 2012 R2 Benchmark v2.1.0',
          ou      => 'Domain Controllers',
        },
      }
      create_resources(windows_cis::group_policy::ensure_gpo, $gpos)
    }
    default: {
    }
  }
}

# Filter Group Policy settings based on the target Group Policy 
#
define windows_cis::group_policy::setting (
  $group_policies,
  $registry_type,
  $registry_value
) {
  $registry_hive = split($name, ':')
  $registry_path = $registry_hive[0]
  $registry_key  = $registry_hive[1]
  $array_count   = count($group_policies)
  
  case $::domain_role {
    'domain_controller': {
      # This policy setting can be present in up to two group policies and enforced
      # on up to two respective OUs, so handle both cases if necessary
      #
      if ($array_count == 1) {
        $policy   = $group_policies[0] 
        $policies = {
          "${policy}:${registry_path}:${registry_key}" => { 
            registry_value => $registry_value, 
            registry_type  => $registry_type 
          },
        }
      } else {
        $controller_policy = $group_policies[0]
        $member_policy     = $group_policies[1]
        $policies          = {
          "${controller_policy}:${registry_path}:${registry_key}" => { 
            registry_value => $registry_value, 
            registry_type  => $registry_type 
          },
          "${member_policy}:${registry_path}:${registry_key}" => { 
            registry_value => $registry_value, 
            registry_type  => $registry_type 
          },
        }
      }
      create_resources(windows_cis::group_policy::apply, $policies)
    }
    default: {
    }
  }
}

# Apply the Group Policy setting
#
define windows_cis::group_policy::apply (
  $registry_value,
  $registry_type
) {
  $policy        = split($name, '[:]')
  $group_policy  = $policy[0]
  $registry_path = $policy[1]
  $registry_key  = $policy[2]

  # Registry values may need to be quoted depending 
  # on the data type of the registry key
  #
  $quote = $registry_type ? { 
    /string/ => "'",
    default  => '',
  }
  
  # Ensure that the setting is applied to the appropriate group policy
  #
  exec { "${group_policy} setting: ${registry_path}:${registry_key}": 
    command  => "Set-GPRegistryValue -Guid (Get-GPO '${group_policy}').Id.Guid -Key '${registry_path}' -ValueName '${registry_key}' -Type '${registry_type}' -Value ${quote}${registry_value}${quote}",
    unless   => "Get-GPRegistryValue -Name '${group_policy}' -Key '${registry_path}' -EA SilentlyContinue | ForEach { if (\$_.ValueName -eq '${registry_key}' -And \$_.PolicyState -eq 'Set' -And \$_.Value -eq ${quote}${registry_value}${quote}) { Return [int]\$True } }",
    provider => powershell,
    require  => Class['windows_cis::group_policy'],
    notify   => Exec['gpupdate /force'],
  }
}

# Create a Group Policy Object and link it to the appropriate Organizational Unit
#
define windows_cis::group_policy::ensure_gpo (
  $comment,
  $ou
) {
  case $::domain_role {
    'domain_controller': {
      # Get the DN components
      #
      $dn_components = split($::domain, '[.]')
      $dn_toplevel   = $dn_components[-1]
      $dn_domain     = $dn_components[-2]   
      $target        = "OU=${ou},DC=${dn_domain},DC=${dn_toplevel}"
      
      # Ensure the Organizational Unit is present
      #
      exec { "Ensure Organizational Unit for '${name}'":
        command  => "New-ADOrganizationalUnit -Name '${ou}' -Path 'DC=${dn_domain},DC=${dn_toplevel}'",
        unless   => "(Get-ADOrganizationalUnit -Filter \"Name -like '${ou}'\" -EA SilentlyContinue).Name | findstr /i /c:\'${ou}'",
        provider => powershell,
        notify   => Exec['gpupdate /force'],
      }
      
      # Ensure that new computer objects are redirected to the new 
      # 'Domain Computers' Organizational Unit by default
      #
      exec { "redircmp '${name}' to '${target}'":
        refreshonly => true,
        command     => "redircmp '${target}'",
        unless      => "redircmp '${target}' | findstr /i /c:'Redirection was successful'",
        provider    => powershell,
        require     => Exec["Ensure Organizational Unit for '${name}'"],
        notify      => Exec['gpupdate /force'],
      }
      
      # Ensure the GPO link is present
      #
      exec { "Ensure Group Policy and Organizational Unit Link '${name}'":
        command  => "New-GPO -Name '${name}' -Comment '${comment}' | New-GPLink -Target \"${target}\" | Set-GPLink -LinkEnabled 'Yes' -Enforced 'Yes' -Order 1",
        unless   => "(Get-GPO '${name}' -EA SilentlyContinue).DisplayName | findstr /i /c:'${name}'",
        provider => powershell,
        require  => Exec["Ensure Organizational Unit for '${name}'"],
        notify   => Exec['gpupdate /force'],
      }
    }
    default: {
    }
  }
}
