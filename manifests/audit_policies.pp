class windows_cis::audit_policies {
  $audit_policies = {
    # CIS: 17 Advanced Audit Policy Configuration
    #
    # CIS: 17.1 Account Logon
    #
    
    # CIS: 17.1.1 (L1) Set 'Audit Credential Validation' to 'Success and Failure' (Scored)
    # References: CCE-37741-6
    # 
    'Credential Validation'           => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'enable',
    },
    
    # CIS: 17.2 Account Management
    #
    
    # 17.2.1 (L1) Set 'Audit Application Group Management' to 'Success and Failure' (Scored)    
    # References: CCE-38329-9
    #
    'Application Group Management'    => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'enable',
    },
    
    # CIS: 17.2.2 (L1) Set 'Audit Computer Account Management' to 'Success and Failure' (Scored)
    # References: CCE-38004-8
    #
    'Computer Account Management'     => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'enable',
    },
    
    # CIS: 17.2.3 (L1) Set 'Audit Distribution Group Management' to 'Success and Failure' (DC only) (Scored)
    # References: CCE-36265-7
    #
    'Distribution Group Management'   => {
      domain_roles => [ 'domain_controller' ],
      success      => 'enable',
      failure      => 'enable',
    },   
    
    # CIS: 17.2.4 (L1) Set 'Audit Other Account Management Events' to 'Success and Failure' (Scored)
    # References: CCE-37855-4
    #
    'Other Account Management Events' => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success     => 'enable',
      failure     => 'enable',
    },
    
    # CIS: 17.2.5 (L1) Set 'Audit Security Group Management' to 'Success and Failure' (Scored)
    # References: CCE-38034-5
    #
    'Security Group Management'       => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'enable',
    },
    
    # CIS: 17.2.6 (L1) Set 'Audit User Account Management' to 'Success and Failure' (Scored)
    # References: CCE-37856-2
    #
    'User Account Management'         => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'enable',
    },
    
    # CIS: 17.3 Detailed Tracking
    #
    
    # CIS: 17.3.1 (L1) Set 'Audit Process Creation' to 'Success' (Scored)
    # References: CCE-36059-4
    #
    'Process Creation'                => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'disable',
    },   
 
    # CIS: 17.4 DS Access
    #
    
    # CIS: 17.4.1 (L1) Set 'Audit Directory Service Access' to 'Success and Failure' (DC only) (Scored)
    # References: CCE-37433-0
    'Directory Service Access'        => {
      domain_roles => [ 'CIS Domain Controller Policy' ],
      success      => 'enable',
      failure      => 'enable',
    },

    # CIS: 17.4.2 (L1) Set 'Audit Directory Service Changes' to 'Success and Failure' (DC only) (Scored)
    # References: CCE-37616-0
    #
    'Directory Service Changes'       => {
      domain_roles => [ 'CIS Domain Controller Policy' ],
      success      => 'enable',
      failure      => 'enable',
    },    

    # CIS: 17.5 Logon/Logoff
    #
    
    # CIS: 17.5.1 (L1) Set 'Audit Account Lockout' to 'Success' (Scored)
    # References: . CCE-37133-6
    #
    'Account Lockout'                 => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'disable',
    },
    
    # CIS: 17.5.2 (L1) Set 'Audit Logoff' to 'Success' (Scored)
    # References: CCE-38237-4
    #
    'Logoff'                          => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'disable',
    },    
 
    # CIS: 17.5.3 (L1) Set 'Audit Logon' to 'Success and Failure' (Scored)
    # References: CCE-37433-0
    #
    'Logon'                           => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'enable',
    },   
    
    # CIS: 17.5.4 (L1) Set 'Audit Other Logon/Logoff Events' to 'Success and Failure' (Scored)
    # References: CCE-36322-6
    #
    'Other Logon/Logoff Events'       => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'enable',
    },  

    # CIS: 17.5.5 (L1) Set 'Audit Special Logon' to 'Success' (Scored)
    # References: CCE-36266-5
    #
    'Special Logon'                   => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'disable',
    }, 

    # CIS: 17.6 Object Access
    #
    
    # CIS: 17.6.1 (L1) Set 'Audit Removable Storage' to 'Success and Failure'  (Scored)
    # References: CCE-37617-8
    # NOTE: Included despite cloud-based instances
    #
    'Removable Storage'               => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'enable',
    }, 
    
    # CIS: 17.7 Policy Change
    #
    
    # CIS: 17.7.1 (L1) Set 'Audit Audit Policy Change' to 'Success and Failure' (Scored)
    # References: CCE-38028-7
    #
    'Audit Policy Change'             => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'enable',
    },  
    
    # CIS: 17.7.2 (L1) Set 'Audit Authentication Policy Change' to 'Success' (Scored)
    # References: CCE-38327-3
    #
    'Authentication Policy Change'    => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'enable',
    }, 
    
    # CIS: 17.8 Privilege Use
    #
    
    # CIS: 17.8.1 (L1) Set 'Audit Sensitive Privilege Use' to 'Success and Failure' (Scored)
    # References: CCE-36267-3
    #
    'Sensitive Privilege Use'         => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'enable',
    }, 
    
    # CIS: 17.9 System
    #
    
    # CIS: 17.9.1 (L1) Set 'Audit IPsec Driver' to 'Success and Failure' (Scored)
    # References: CCE-37853-9
    #
    'IPsec Driver'                    => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'enable',
    },

    # CIS: 17.9.2 (L1) Set 'Audit Other System Events' to 'Success and Failure' (Scored)
    # References: CCE-38030-3
    #
    'Other System Events'             => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'enable',
    },

    # CIS: 17.9.3 (L1) Set 'Audit Security State Change' to 'Success and Failure' (Scored)
    # References: CCE-38030-3
    #
    'Security State Change'           => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'enable',
    },

    # CIS: 17.9.4 (L1) Set 'Audit Security System Extension' to 'Success and Failure' (Scored)
    # References: CCE-36144-4
    #
    'Security System Extension'       => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'enable',
    },

    # CIS: 17.9.5 (L1) Set 'Audit System Integrity' to 'Success and Failure' (Scored)
    # References: CCE-37132-8
    #
    'System Integrity'                => {
      domain_roles => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      success      => 'enable',
      failure      => 'enable',
    }
  }
  
  create_resources(windows_cis::audit_policies::apply, $audit_policies)
}

define windows_cis::audit_policies::apply(
  $domain_roles,
  $success,
  $failure
) {
  $role = {
    domain_controller => 'CIS Domain Controller Policy',
    member_server     => 'CIS Domain Policy',
    standalone_server => 'No Domain Policy',
  }
  
  if ( $role[$::domain_role] in $domain_roles ) {
    auditpol { "${name}":
      success     => $success,
      failure     => $failure,
    }
  }
}
