class windows_cis::security_options {
  require windows_cis::group_policy

  $gpo_settings = {
    # Author's note: Multistring (REG_MULTI_SZ) type registry keys are written 
    # out in PowerShell array notation; e.g., @("element1", "element2"). Arrays  
    # are written in this format in order to present PowerShell with "live",
    # native objects for object comparison in the processing pipeline
    #
    
    # CIS: 2.3 Security Options
    # This section contains recommendations for security options
    #
    
    # CIS: 2.3.2 Audit
    # This section contains recommendations related to auditing controls
    #
    
    # CIS: 2.3.2.1 (L1) Set 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' to 'Enabled' (Scored)
    # References: CCE-37850-5
    #
    'HKLM\System\CurrentControlSet\Control\Lsa:scenoapplylegacyauditpolicy' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,         
    },  
    
    # CIS: 2.3.2.2 (L1) Set 'Audit: Shut down system immediately if unable to log security audits' to 'Disabled' (Scored)
    # References: CCE-35907-5
    #
    'HKLM\System\CurrentControlSet\Control\Lsa:crashonauditfail'  => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,      
    },
    
    # CIS: 2.3.3 DCOM
    # This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.
    #
    
    # CIS: 2.3.4 Devices
    # This section contains recommendations related to managing devices.
    #
    
    # CIS: 2.3.4.1 (L1) Set 'Devices: Allowed to format and eject removable media' to 'Administrators' (Scored)
    # References: CCE-37701-0
    #
    'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon:AllocateDASD' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'string',
      registry_value    => 0,  
    },
    
    # CIS: 2.3.4.2 (L1) Set 'Devices: Prevent users from installing printer drivers' to 'Enabled' (Scored)
    # References: CCE-37942-0
    #
    'HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers:AddPrinterDrivers' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    },
    
    # CIS: 2.3.5 Domain controller
    # This section contains recommendations related to domain controllers
    #
    # CIS: 2.3.5.1 (L1) Set 'Domain controller: Allow server operators to schedule tasks' to 'Disabled' (DC only) (Scored)
    # References: CCE-37848-9
    #
    'HKLM\System\CurrentControlSet\Control\Lsa:SubmitControl' => {
      group_policies    => [ 'CIS Domain Controller Policy' ],
      registry_type     => 'dword',
      registry_value    => 0,  
    },

    # CIS: 2.3.5.2 (L1) Set 'Domain controller: LDAP server signing requirements' to 'Require signing' (DC only) (Scored)
    # References: CCE-35904-2
    #
    'HKLM\System\CurrentControlSet\Services\NTDS\Parameters:ldapserverintegrity' => {
      group_policies    => [ 'CIS Domain Controller Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    },
	  
    # CIS: 2.3.5.3 (L1) Set 'Domain controller: Refuse machine account password changes' to 'Disabled' (DC only) (Scored)
    # References: CCE-36921-5
    #
    'HKLM\System\CurrentControlSet\Services\Netlogon\Parameters:RefusePasswordChange' => {
      group_policies    => [ 'CIS Domain Controller Policy' ],
      registry_type     => 'dword',
      registry_value    => 2,  
    },
    
    # CIS: 2.3.6 Domain member
    # This section contains recommendations related to domain membership
    #
    
    # CIS: 2.3.6.1 (L1) Set 'Domain member: Digitally encrypt or sign secure channel data (always)' to 'Enabled' (Scored)
    # References: CCE-36142-8
    #
    'HKLM\System\CurrentControlSet\Services\Netlogon\Parameters:requiresignorseal' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    },
    
    # CIS: 2.3.6.2 (L1) Set 'Domain member: Digitally encrypt secure channel data (when possible)' to 'Enabled' (Scored)
    # References: CCE-37130-2
    #
    'HKLM\System\CurrentControlSet\Services\Netlogon\Parameters:sealsecurechannel' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    },
    
    # CIS: 2.3.6.3 (L1) Set 'Domain member: Digitally sign secure channel data (when possible)' to 'Enabled' (Scored)
    # References: CCE-37222-7
    #
    'HKLM\System\CurrentControlSet\Services\Netlogon\Parameters:signsecurechannel' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    },
    
    # CIS: 2.3.6.4 (L1) Set 'Domain member: Disable machine account password changes' to 'Disabled' (Scored)
    # References: CCE-37508-9
    #
    'HKLM\System\CurrentControlSet\Services\Netlogon\Parameters:disablepasswordchange' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 0,  
    },
    
    # CIS: 2.3.6.5 (L1) Set 'Domain member: Maximum machine account password age' to '30 or fewer days, but not 0' (Scored)
    # References: CCE-37431-4
    # The recommended state for this setting is: 30 or fewer days, but not 0
    # Default Value: 30 days
    #

    # CIS: 2.3.6.6 (L1) Set 'Domain member: Require strong (Windows 2000 or later) session key' to 'Enabled' (Scored)
    # References: CCE-37614-5
    #
    'HKLM\System\CurrentControlSet\Services\Netlogon\Parameters:requirestrongkey' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    }, 
    
    # CIS: 2.3.7 Interactive logon
    # This section contains recommendations related to interactive logons
    #
    
    # CIS: 2.3.7.1 (L1) Set 'Interactive logon: Do not display last user name' to 'Enabled' (Scored)
    # References: CCE-36056-0
    #
    'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System:DontDisplayLastUserName' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    },    

    # CIS: 2.3.7.2 (L1) Set 'Interactive logon: Do not require CTRL+ALT+DEL' to 'Disabled' (Scored)
    # References: CCE-37637-6
    #
    'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System:DisableCAD' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    }, 
    
    # CIS: 2.3.7.3 (L1) Set 'Interactive logon: Machine inactivity limit' to '900 or fewer second(s), but not 0' (Scored)
    # References: CCE-38235-8
    # NOTE: Benchmark commented out for development
    #
    'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System:InactivityTimeoutSecs' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'dword',
      registry_value    => 384,         
    },
    
    # CIS: 2.3.7.4 (L1) Configure 'Interactive logon: Message text for users attempting to log on' (Scored)
    # References: CCE-37226-8
    #
    'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System:LegalNoticeText' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'string',
      registry_value    => 'This is a private system, restricted to authorized users only. All activities on this system are monitored and recorded. Unauthorized users, access, and/or modification will be fully investigated and reported to the appropriate law enforcement agencies.',  
    }, 
    
    # CIS: 2.3.7.5 (L1) Configure 'Interactive logon: Message title for users attempting to log on' (Scored)
    # References: CCE-37512-1
    #
    'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System:LegalNoticeCaption' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'string',
      registry_value    => 'This system is restricted to authorized users only.',  
    },  
    
    # CIS: 2.3.7.6 (L1) Set 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' to '4 or fewer logon(s)' (MS only) (Scored)
    # References:    CCE-37439-7
    #
    'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon:cachedlogonscount' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'string',
      registry_value    => '4',  
    },  
    
    # CIS: 2.3.7.7 (L1) Set 'Interactive logon: Prompt user to change password before expiration' to 'between 5 and 14 days' (Scored)
    # References: CCE-37622-8
    #    
    'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon:passwordexpirywarning' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 5,  
    }, 
    
    # CIS: 2.3.7.8 (L1) Set 'Interactive logon: Require Domain Controller Authentication to unlock workstation' to 'Enabled' (MS only) (Scored)
    # References: CCE-37622-8
    # TODO: Evaluate the impact of this benchmark in cloud environments
    #
    'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon:ForceUnlockLogon' => {
      group_policies    => [ 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 5,  
    }, 
    
    # CIS: 2.3.7.9 (L1) Set 'Interactive logon: Smart card removal behavior' to 'Lock Workstation' or higher (Scored)
    # References: CCE-38333-1
    # TODO: Evaluate the impact of this benchmark in cloud environments
    #  
    'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon:scremoveoption' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'string',
      registry_value    => '1',  
    },
    
    # CIS: 2.3.8 Microsoft network client
    # This section contains recommendations related to configuring the Microsoft network client
    #
    
    # CIS: 2.3.8.1 (L1) Set 'Microsoft network client: Digitally sign communications (always)' to 'Enabled' (Scored)
    # References: CCE-36325-9
    #
    'HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters:RequireSecuritySignature' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 0,  
    },

    # CIS: 2.3.8.2 (L1) Set 'Microsoft network client: Digitally sign communications (if server agrees)' to 'Enabled' (Scored)
    # References: CCE-36269-9
    #
    'HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters:EnableSecuritySignature' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    },
    
    # CIS: 2.3.8.3 (L1) Set 'Microsoft network client: Send unencrypted password to third-party SMB servers' to 'Disabled' (Scored)
    # References: CCE-37863-8
    #    
    'HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters:EnablePlainTextPassword' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 0,  
    }, 
    
    # CIS: 2.3.9 Microsoft network server
    # This section contains recommendations related to configuring the Microsoft network server
    #
    
    # CIS: 2.3.9.1 (L1) Set 'Microsoft network server: Amount of idle time required before suspending session' to '15 or fewer minute(s), but not 0' (Scored)
    # References: CCE-38046-9
    #
    'HKLM\System\CurrentControlSet\Services\LanManServer\Parameters:autodisconnect' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 15,  
    },  
    
    # CIS: 2.3.9.2 (L1) Set 'Microsoft network server: Digitally sign communications (always)' to 'Enabled' (Scored)
    # References: CCE-37864-6
    #
    'HKLM\System\CurrentControlSet\Services\LanManServer\Parameters:requiresecuritysignature' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    },  
    
    # CIS: 2.3.9.3 (L1) Set 'Microsoft network server: Digitally sign communications (if client agrees)' to 'Enabled' (Scored)
    # References: CCE-35988-5
    #
    'HKLM\System\CurrentControlSet\Services\LanManServer\Parameters:enablesecuritysignature' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    }, 
    
    # CIS: 2.3.9.4 (L1) Set 'Microsoft network server: Disconnect clients when logon hours expire' to 'Enabled' (Scored)
    # References: CCE-37972-7
    #
    'HKLM\System\CurrentControlSet\Services\LanManServer\Parameters:enableforcedlogoff' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    },  
    
    # CIS: 2.3.9.5 (L1) Set 'Microsoft network server: Server SPN target name validation level' to 'Accept if provided by client' or higher (Scored)
    # References: CCE-36170-9
    #
    'HKLM\System\CurrentControlSet\Services\LanManServer\Parameters:SMBServerNameHardeningLevel' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 2,  
    }, 
    
    # CIS: 2.3.10 Network access
    # This section contains recommendations related to network access
    #
    
    # CIS: 2.3.10.2 (L1) Set 'Network access: Do not allow anonymous enumeration of SAM accounts' to 'Enabled' (Scored)
    # References: CCE-36316-8
    #
    'HKLM\System\CurrentControlSet\Control\Lsa:RestrictAnonymousSAM' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    }, 
    
    # CIS: 2.3.10.3 (L1) Set 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' to 'Enabled' (Scored)
    # References: CCE-36077-6
    #
     'HKLM\System\CurrentControlSet\Control\Lsa:RestrictAnonymous' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    }, 
    
    # CIS: 2.3.10.4 (L2) Set 'Network access: Do not allow storage of passwords and credentials for network authentication' to 'Enabled' (Scored)
    # References: CCE-38119-4
    #
    'HKLM\System\CurrentControlSet\Control\Lsa:disabledomaincreds' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    },

    # CIS: 2.3.10.5 (L1) Set 'Network access: Let Everyone permissions apply to anonymous users' to 'Disabled' (Scored)
    # References: CCE-36148-5
    #
    'HKLM\System\CurrentControlSet\Control\Lsa:EveryoneIncludesAnonymous' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    },
    
    # CIS: 2.3.10.6 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously' (Scored)
    # References: CCE-38258-0
    #
    'HKLM\System\CurrentControlSet\Services\LanManServer\Parameters:NullSessionPipes' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'multistring',
      registry_value    => '@("LSARPC", "BROWSER", "netlogon", "samr")',
    },
    
    # CIS: 2.3.10.7 (L1) Set 'Network access: Remotely accessible registry paths' (Scored)
    # References: CCE-37194-8
    #
    'HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths:Machine' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'multistring',
      registry_value   => '@("System\CurrentControlSet\Control\ProductOptions", "System\CurrentControlSet\Control\Server Applications", "Software\Microsoft\Windows NT\CurrentVersion")',
    },

    # CIS: 2.3.10.8 (L1) Set 'Network access: Remotely accessible registry paths and sub-paths' (Scored)
    # References: CCE-36347-3
    #
    # TODO: *Active Directory Certificate Services* Role and *Certification Authority* Role Service include: 
    #       System\CurrentControlSet\Services\CertSvc
    #
    'HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths:Machine' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'multistring',
      registry_value   => '@("System\CurrentControlSet\Control\Print\Printers", "System\CurrentControlSet\Services\Eventlog", "Software\Microsoft\OLAP Server", "Software\Microsoft\Windows NT\CurrentVersion\Print", "Software\Microsoft\Windows NT\CurrentVersion\Windows", "System\CurrentControlSet\Control\ContentIndex", "System\CurrentControlSet\Control\Terminal Server", "System\CurrentControlSet\Control\Terminal Server\UserConfig", "System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration", "Software\Microsoft\Windows NT\CurrentVersion\Perflib", "System\CurrentControlSet\Services\SysmonLog")',
    },

    # CIS: 2.3.10.9 (L1) Set 'Network access: Restrict anonymous access to Named Pipes and Shares' to 'Enabled' (Scored)
    # References: CCE-36021-4
    #
    'HKLM\System\CurrentControlSet\Services\LanManServer\Parameters:RestrictNullSessAccess' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'dword',
      registry_value    => 1,  
    },

    # CIS: 2.3.10.10 (L1) Set 'Network access: Shares that can be accessed anonymously' to 'None' (Scored)
    # References: CCE-38095-6
    #
    'HKLM\System\CurrentControlSet\Services\LanManServer\Parameters:nullsessionshares' => {
      group_policies    => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type     => 'multistring',
      registry_value    => '@("")',         
    },
    
    # CIS: 2.3.10.11 (L1) Set 'Network access: Sharing and security model for local accounts' to 'Classic - local users authenticate as themselves' (Scored)
    # References: CCE-37623-6
    #
    'HKLM\System\CurrentControlSet\Control\Lsa:ForceGuest' => {
      group_policies   => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'dword',
      registry_value   => '0',         
    },
    
    # CIS: 2.3.11 Network security
    # This section contains recommendations related to network security
    #
    
    # CIS: 2.3.11.1 (L1) Set 'Network security: Allow Local System to use computer identity for NTLM' to 'Enabled' (Scored)
    # References: CCE-37623-6
    #
    'HKLM\System\CurrentControlSet\Control\Lsa:usemachineid' => {
      group_policies   => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'dword',
      registry_value   => 1,       
    },
    
    # CIS: 2.3.11.2 (L1) Set 'Network security: Allow LocalSystem NULL session fallback' to 'Disabled' (Scored)
    # References: CCE-37035-3
    #
    'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0:allownullsessionfallback' => {
      group_policies   => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'dword',
      registry_value   => 0, 
    },
    
    
    # CIS: 2.3.11.3 (L1) Set 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' to 'Disabled' (Scored)
    # References: CCE-38047-7
    #
    'HKLM\System\CurrentControlSet\Control\Lsa\pku2u:AllowOnlineID' => {
      group_policies   => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'dword',
      registry_value   => 0,
    },

    # CIS: 2.3.11.4 (L1) Set 'Network Security: Configure encryption types allowed for Kerberos' to 'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' (Scored)
    # References: CCE-37755-6
    #
    'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters:SupportedEncryptionTypes' => {
      group_policies   => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'multistring', 
      registry_value   => '@("DES_CBC_CRC", "DES_CBC_MD5", "RC4_HMAC_MD5", "AES128_HMAC_SHA1", "AES256_HMAC_SHA1", "Future encryption types")', 
    },
    
    # CIS: 2.3.11.5 (L1) Set 'Network security: Do not store LAN Manager hash value on next password change' to 'Enabled' (Scored)
    # References: CCE-36326-7
    #
    'HKLM\System\CurrentControlSet\Control\Lsa:NoLMHash' => {
      group_policies   => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'dword',
      registry_value   => 1,     
    },
    
    # CIS : 2.3.11.6 (L1) Set 'Network security: Force logoff when logon hours expire' to 'Enabled' (Scored)
    # References: CCE-36270-7
    #
    'HKLM\System\CurrentControlSet\Services\LanManServer\Parameters:enableforcedlogoff' => {
      group_policies   => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'dword',
      registry_value   => 1,      
    },

    # CIS: 2.3.11.7 (L1) Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM & NTLM' (Scored)
    # References: CCE-36173-3
    # 
    'HKLM\System\CurrentControlSet\Control\Lsa:LmCompatibilityLevel' => {
      group_policies   => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'dword',
      registry_value   => 5,       
    },
    
    # CIS: 2.3.11.8 (L1) Set 'Network security: LDAP client signing requirements' to 'Negotiate signing or higher' (Scored)
    # References: CCE-36858-9
    # 
    'HKLM\System\CurrentControlSet\Services\LDAP:LDAPClientIntegrity' => {
      group_policies   => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'dword',
      registry_value   => 1,    
    },
    
    # CIS: 2.3.11.9 (L1) Set 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' to 'Require NTLMv2 session security, Require 128-bit encryption' (Scored)
    # References: CCE-37553-5
    #
    'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0:NTLMMinServerSec' => {
      group_policies   => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'dword',
      registry_value   => '0x20080030', 
    },
    
    # CIS: 2.3.11.10 (L1) Set 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' to 'Require NTLMv2 session security, Require 128-bit encryption' (Scored)
    # References: CCE-37835-6
    #
    'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0:NTLMMinServerSec' => {
      group_policies   => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'dword',
      registry_value   => '0x20080030', 
    },
    
    # CIS: 2.3.12 Recovery console
    # This section contains recommendations related to the recovery console
    # References: CCE-37624-4; CCE-37307-6
    #
    
    # CIS: 2.3.13 Shutdown
    # This section contains recommendations related to the Windows shutdown functionality
    # References: CCE-36788-8
    #
    
    # CIS: 2.3.14 System cryptography
    # This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent
    #
    
    # CIS: 2.3.15 System objects
    # This section contains recommendations related to system objects
    
    # CIS: 2.3.15.1 (L1) Set 'System objects: Require case insensitivity for nonWindows subsystems' to 'Enabled' (Scored)
    # References: CCE-37885-1
    # The recommended state for this setting is: Enabled
    # Default Value: Enabled
    #
    
    # CIS: 2.3.15.2 (L1) Set 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' to 'Enabled' (Scored)
    # References: CCE-37644-2
    #
    'HKLM\System\CurrentControlSet\Control\Session Manager:ProtectionMode' => {
      group_policies   => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'dword',
      registry_value   => 1,        
    },
    
    # CIS: 2.3.16 System settings
    # This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.
    #
    
    # CIS: 2.3.17 User Account Control
    # This section contains recommendations related to User Account Control
    # NOTE: The majority of the following 'userland' benchmarks are ommitted 
    # because they can interfere with automation tasks
    # 
    
    # CIS: 2.3.17.1 (L1) Set 'User Account Control: Admin Approval Mode for the Built-in Administrator account' to 'Enabled' (Scored)
    # References: CCE-36494-3
    #
    
    # CIS: 2.3.17.2 (L1) Set 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' to 'Disabled' (Scored)
    # References: CCE-36863-9
    # 
    
    # CIS: 2.3.17.3 (L1) Set 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' to 'Prompt for consent on the secure desktop' (Scored) 
    # References: CCE-37029-6
    #
    
    # CIS: 2.3.17.4 (L1) Set 'User Account Control: Behavior of the elevation prompt for standard users' to 'Automatically deny elevation requests' (Scored)
    # References: CCE-36864-7
    #
    'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System:ConsentPromptBehaviorUser' => {
      group_policies   => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'dword',
      registry_value   => 0,         
    },
    
    # CIS: 2.3.17.5 (L1) Set 'User Account Control: Detect application installations and prompt for elevation' to 'Enabled' (Scored)
    # References: CCE-36533-8
    #
    
    # CIS: 2.3.17.6 (L1) Set 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' to 'Enabled' (Scored)
    # References: CCE-37057-7
    #
    
    # CIS: 2.3.17.7 (L1) Set 'User Account Control: Run all administrators in Admin Approval Mode' to 'Enabled' (Scored)
    # References: CCE-36869-6
    #
    
    # CIS: 2.3.17.8 (L1) Set 'User Account Control: Switch to the secure desktop when prompting for elevation' to 'Enabled' (Scored)
    # References: CCE-36866-2
    #
    
    # CIS: 2.3.17.9 (L1) Set 'User Account Control: Virtualize file and registry write failures to per-user locations' to 'Enabled' (Scored)
    # References: CCE-37064-3
    #
    'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System:EnableVirtualization' => {
      group_policies   => [ 'CIS Domain Controller Policy', 'CIS Domain Policy' ],
      registry_type    => 'dword',
      registry_value   => 1,         
    },
  } 
  create_resources(windows_cis::group_policy::setting, $gpo_settings)
}