Facter.add("domain_role") do
  confine :kernel => :windows
  setcode do
    standalone_server = Facter::Util::Resolution.exec('C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -Command ($Env:Computername -eq $Env:Userdomain)')
    if standalone_server == 'True'
      'standalone_server'
    else
      domain_controller = Facter::Util::Resolution.exec('C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -Command (Get-ADDomainController -EA SilentlyContinue).Enabled')
      if domain_controller
        'domain_controller'
      else
        'member_server'
     end
    end
  end
end
