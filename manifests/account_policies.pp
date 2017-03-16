# Author's note: Please see this article on Well-Known SID Structures
# https://msdn.microsoft.com/en-us/library/cc980032.aspx
#
class windows_cis::account_policies {
  $account_policies = {
    # CIS: 1 Account Policies
    # This section contains recommendations for account policies.
    #
    # 1.1 Password Policy
    # This section contains recommendations for password policy.
    #
    
    # CIS: 1.1.1 (L1) Set 'Enforce password history' to '24 or more password(s)' (Scored)
    # References: CCE-37166-6
    #
    'Enforce password history' => {   
      domain_roles   => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      policy_value   => '24', 
    },
    
    # CIS: 1.1.2 (L1) Set 'Maximum password age' to '60 or fewer days, but not 0' (Scored)
    # References: CCE-37167-4
    #
    'Maximum password age' => {   
      domain_roles   => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      policy_value   => '60', 
    },   
    
    # CIS: 1.1.3 (L1) Set 'Minimum password age' to '1 or more day(s)' (Scored)
    # References: CCE-37073-4
    #
    'Minimum password age' => {   
      domain_roles   => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      policy_value   => '1', 
    }, 
    
    # CIS: 1.1.4 (L1) Set 'Minimum password length' to '14 or more character(s)' (Scored)
    # References: CCE-36534-6
    #
    'Minimum password length' => {   
      domain_roles   => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      policy_value   => '14', 
    },    
    
    # CIS: 1.1.5 (L1) Set 'Password must meet complexity requirements' to 'Enabled' (Scored)
    # References: CCE-37063-5
    #
    'Password must meet complexity requirements' => {   
      domain_roles   => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      policy_value   => '1', 
    },
    
    # CIS: 1.1.6 (L1) Set 'Store passwords using reversible encryption' to 'Disabled' (Scored)
    # References: CCE-36286-3
    # The recommended state for this setting is: Disabled
    # Default Value: Disabled
    #
    
    # CIS: 1.2 Account Lockout Policy
    #
    # CIS: 1.2.1 (L1) Set 'Account lockout duration' to '15 or more minute(s)' (Scored)
    # References: CCE-37034-6
    #
    'Account lockout duration' => {   
      domain_roles   => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      policy_value   => '15', 
      require        => [
        Local_security_policy['Account lockout threshold'],
        Local_security_policy['Reset account lockout counter after'],
      ]
    },
    
    # CIS: 1.2.2 (L1) Set 'Account lockout threshold' to '10 or fewer invalid logon attempt(s), but not 0' (Scored)
    # References: CCE-36008-1
    #
    'Account lockout threshold' => {  
      domain_roles   => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      policy_value   => '10', 
    },
    
    # CIS: 1.2.3 (L1) Set 'Reset account lockout counter after' to '15 or more minute(s)' (Scored)
    # References: CCE-36883-7
    #
    'Reset account lockout counter after' => {  
      domain_roles   => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      policy_value   => '15', 
      require        => Local_security_policy['Account lockout threshold'],
    },  
    
    # CIS: 2 Local Policies
    # This section contains recommendations for local policies.
    #
    # CIS: 2.1 Audit Policy
    # This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.
    #
    
    # CIS: 2.2 User Rights Assignment
    # This setting contains recommendations for user rights assignments.
    #
    
    # 2.2.1 (L1) Set 'Access Credential Manager as a trusted caller' to 'No One' (Scored)
    # References: CCE-37056-9
    # The recommended state for this setting is: No One.
    # Default Value: No one.
    #
  
    # CIS: 2.2.2 (L1) Configure 'Access this computer from the network' (Scored)
    # References: CCE-35818-4
    #
    'Access this computer from the network' => {  
      domain_roles   => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      policy_value   => $::domain_role ? { 
        'domain_controller' => 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS',
        default             => '*S-1-5-11,*S-1-5-32-544', #'Administrators, Authenticated Users',
      },
    },


    # CIS: 2.2.3 (L1) Set 'Act as part of the operating system' to 'No One' (Scored)
    # References: CCE-36876-1
    # NOTE: This benchmark omitted because it can interfere with automation tasks.
    #

    # CIS: 2.2.4 (L1) Set 'Add workstations to domain' to 'Administrators' (DC only) (Scored)
    # References: CCE-36876-1
    # NOTE: This benchmark omitted because it can interfere with automation tasks.
    #

    # CIS: 2.2.5 (L1) Set 'Adjust memory quotas for a process' to 'Administrators, LOCAL SERVICE, NETWORK SERVICE' (Scored)
    # References: CCE-37071-8
    # NOTE: This benchmark is omitted because it should be configured based on application role.
    #
    
    # CIS: 2.2.6 (L1) Configure 'Allow log on locally' (Scored)
    # References: CCE-37659-0
    # The recommended state for this setting is: Administrators
    # Default Value: Administrators, Users, Backup Operators
    #
    
    # CIS: 2.2.7 (L1) Configure 'Allow log on through Remote Desktop Services' (Scored)
    # References: CCE-37072-6
    # The recommended state for this setting is: Administrators, Remote Desktop Users
    # Default Value: Administrators, Remote Desktop Users
    #
    
    # CIS: 2.2.8 (L1) Set 'Back up files and directories' to 'Administrators' (Scored)
    # References: CCE-35912-5
    #
    'Back up files and directories' => {
      domain_roles   => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      policy_value   => 'Administrators',
    },

    # CIS: 2.2.9 (L1) Set 'Change the system time' to 'Administrators, LOCAL SERVICE' (Scored)
    # References: CCE-37452-0
    # The recommended state for this setting is: Administrators, LOCAL SERVICE
    # Default Value: Administrators, LOCAL SERVICE
    #
    
    # CIS: 2.2.10 (L1) Set 'Change the time zone' to 'Administrators, LOCAL SERVICE' (Scored)
    # References: CCE-37700-2
    # The recommended state for this setting is: Administrators, LOCAL SERVICE
    # Default Value: Administrators, LOCAL SERVICE
    #
    
    # CIS: 2.2.11 (L1) Set 'Create a pagefile' to 'Administrators' (Scored)
    # References: CCE-35821-8
    # The recommended state for this setting is: Administrators
    # Default Value: Administrators.
    #
    
    # CIS: 2.2.12 (L1) Set 'Create a token object' to 'No One' (Scored)
    # References: CCE-36861-3
    # The recommended state for this setting is: No One
    # Default Value: No one
    #

    # CIS: 2.2.13 (L1) Set 'Create global objects' to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (Scored)
    # References: CCE-37453-8
    # The recommended state for this setting is: Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE.
    # Default Value: Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE.
    #
    
    # CIS: 2.2.14 (L1) Set 'Create permanent shared objects' to 'No One' (Scored)
    # References: CCE-36532-0
    # The recommended state for this setting is: No One
    # Default Value: No one
    #
    
    # CIS: 2.2.15 (L1) Configure 'Create symbolic links' (Scored)
    # References: CCE-35823-4
    # NOTE: This benchmark is omitted because it's Hyper-V specific.
    #
    
    # CIS: 2.2.16 (L1) Set 'Debug programs' to 'Administrators' (Scored)
    # References: CCE-37075-9
    # NOTE: The recommended state for this setting is: Administrators
    # Default Value: Administrators.
    #
    
    # CIS: 2.2.17 (L1) Configure 'Deny access to this computer from the network' (Scored)
    # References: CCE-37954-5
    # The recommended state for this setting is to include: Guests, Local account and member of Administrators group
    # Default Value: Guest
    #
    
    # CIS: 2.2.18 (L1) Set 'Deny log on as a batch job' to include 'Guests' (Scored)
    # References: CCE-36923-1
    #
    'Deny log on as a batch job' => {
      domain_roles   => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      policy_value   => 'Guests',
    },

    # CIS: 2.2.19 (L1) Set 'Deny log on as a service' to include 'Guests' (Scored)
    # References: CCE-36877-9
    #
    'Deny log on as a service' => {
      domain_roles   => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      policy_value   => 'Guests',
    },
    
    # CIS: 2.2.20 (L1) Set 'Deny log on locally' to include 'Guests' (Scored)
    # References: CCE-37146-8
    # The recommended state for this setting is to include: Guests
    # Default Value: Guests
    #
    
    # CIS: 2.2.21 (L1) Set 'Deny log on through Remote Desktop Services' to include 'Guests, Local account' (Scored)
    # References: CCE-36867-0
    # The recommended state for this setting is to include: Guests, Local account
    # Default Value: No one
    #
    
    # CIS: 2.2.22 (L1) Configure 'Enable computer and user accounts to be trusted for delegation' (Scored)
    # References: CCE-36860-5
    # The recommended state for this setting is: No One
    # Default Value: No one
    #
    
    # CIS: 2.2.23 (L1) Set 'Force shutdown from a remote system' to 'Administrators' (Scored)
    # References: CCE-37877-8
    # The recommended state for this setting is: Administrators
    # Default Value: Administrators
    #
    
    # CIS: 2.2.24 (L1) Set 'Generate security audits' to 'LOCAL SERVICE, NETWORK SERVICE' (Scored)
    # References: CCE-37639-2
    # The recommended state for this setting is: LOCAL SERVICE, NETWORK SERVICE
    # Default Value: LOCAL SERVICE, NETWORK SERVICE
    #
    
    # CIS: 2.2.25 (L1) Configure 'Impersonate a client after authentication' (Scored)
    # References: CCE-37639-2
    # TODO: Evaluate this benchmark
    #
    
    # CIS: 2.2.26 (L1) Set 'Increase scheduling priority' to 'Administrators' (Scored)
    # References: CCE-38326-5
    # The recommended state for this setting is: Administrators
    # Default Value: Administrators
    #
    
    # CIS: 2.2.27 (L1) Set 'Load and unload device drivers' to 'Administrators' (Scored)
    # References: CCE-36318-4
    # The recommended state for this setting is: Administrators
    # Default Value: Administrators
    #
    
    # CIS: 2.2.28 (L1) Set 'Lock pages in memory' to 'No One' (Scored)
    # References: CCE-36495-0
    # The recommended state for this setting is: No One
    # Default Value: No one
    #
    
    # CIS: 2.2.29 (L1) Configure 'Manage auditing and security log' (Scored)
    # References: CCE-35906-7
    # The recommended state for this setting is: Administrators
    # Default Value: Administrators
    #
    
    # CIS: 2.2.30 (L1) Set 'Modify an object label' to 'No One' (Scored)
    # References:CCE-36054-5
    # The recommended state for this setting is: No One
    # Default Value: None
    #
    
    # CIS: 2.2.31 (L1) Set 'Modify firmware environment values' to 'Administrators' (Scored)
    # References: CCE-38113-7
    # The recommended state for this setting is: Administrators
    # Default Value: Administrators
    #
    
    # CIS: 2.2.32 (L1) Set 'Perform volume maintenance tasks' to 'Administrators' (Scored)
    # References: CCE-36143-6
    # The recommended state for this setting is: Administrators
    # Default Value: Administrators
    #
    
    # CIS: 2.2.33 (L1) Set 'Profile single process' to 'Administrators' (Scored)
    # References: CCE-37131-0
    # The recommended state for this setting is: Administrators
    # Default Value: Administrators
    # 
    
    # CIS: 2.2.34 (L1) Set 'Profile system performance' to 'Administrators, NT SERVICE\WdiServiceHost' (Scored)
    # References: CCE-36052-9
    # The recommended state for this setting is: Administrators, NT SERVICE\WdiServiceHost
    # Default Value: Administrators, NT SERVICE\WdiServiceHost
    # 
    
    # CIS: 2.2.35 (L1) Set 'Replace a process level token' to 'LOCAL SERVICE, NETWORK SERVICE' (Scored)
    # References: CCE-37430-6
    # The recommended state for this setting is: LOCAL SERVICE, NETWORK SERVICE
    # Default Value: LOCAL SERVICE, NETWORK SERVICE
    #
    
    # CIS: 2.2.36 (L1) Set 'Restore files and directories' to 'Administrators' (Scored)
    # References: CCE-37613-7
    #
    'Restore files and directories' => {
      domain_roles   => [ 'CIS Domain Policy', 'CIS Domain Controller Policy', 'No Domain Policy' ],
      policy_value   => 'Administrators',
    },
    
    # CIS: 2.2.38 (L1) Set 'Synchronize directory service data' to 'No One' (DC only) (Scored)
    # References: CCE-36099-0
    # The recommended state for this setting is: No One
    # Default Value: Not defined
    #
    
    # CIS: 2.2.39 (L1) Set 'Take ownership of files or other objects' to 'Administrators' (Scored)
    # References: CCE-38325-7
    # The recommended state for this setting is: Administrators
    # Default Value: Administrators
    #
    
    # CIS: 2.3 Security Options
    # This section contains recommendations for security options
    #
    # CIS: 2.3.1 Accounts
    # This section contains recommendations related to default accounts
    #
    
    # CIS: 2.3.1.1 (L1) Set 'Accounts: Administrator account status' to 'Disabled' (Scored)  
    # References: CCE-37953-7
    # The recommended state for this setting is: Disabled
    # Default Value: Disabled
    #

    # CIS: 2.3.1.2 (L1) Set 'Accounts: Block Microsoft accounts' to 'Users can't add or log on with Microsoft accounts' (Scored)   
    # References: CCE-36147-7
    # The recommended state for this setting is: Users can't add or log on with Microsoft accounts.
    # Default Value: Not defined
    #
    
    # CIS: 2.3.1.3 (L1) Set 'Accounts: Guest account status' to 'Disabled' (Scored)
    # References: CCE-37432-2
    # The recommended state for this setting is: Disabled
    # Default Value: Disabled
    #
    
    # CIS: 2.3.1.4 (L1) Set 'Accounts: Limit local account use of blank passwords to console logon only' to 'Enabled' (Scored)
    # References: CCE-37615-2
    # The recommended state for this setting is: Enabled
    # Default Value: Enabled
    #
    
    # CIS: 2.3.1.5 (L1) Configure 'Accounts: Rename administrator account' (Scored)
    # References: CCE-38233-3
    # This benchmark is omitted because the Administrator account is required for Windows logon in AWS
    # TODO: Revisit this benchmark
    #
    
    # CIS: 2.3.1.6 (L1) Configure 'Accounts: Rename guest account' (Scored)
    # References: CCE-38027-9
    # This benchmark is omitted becasue the Guest account is disabled by default
    #

  }    
  
  create_resources(windows_cis::account_policies::apply, $account_policies)
}

define windows_cis::account_policies::apply(
  $domain_roles,
  $policy_setting = undef,
  $policy_value = undef
) {
  $role = {
    domain_controller => 'CIS Domain Controller Policy',
    member_server     => 'CIS Domain Policy',
    standalone_server => 'No Domain Policy',
  }
  
  if ( $role[$::domain_role] in $domain_roles ) {
    local_security_policy { "${name}":
      policy_setting => $policy_setting,
      policy_value   => $policy_value,
    }
  }
}
