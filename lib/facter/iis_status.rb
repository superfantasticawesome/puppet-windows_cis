Facter.add("iis_status") do
  confine :kernel => :windows
  setcode do
    iis_status = Facter::Util::Resolution.exec("powershell.exe -ExecutionPolicy Unrestricted -Command (Get-Service -ErrorAction SilentlyContinue 'W3SVC').Status")
    if iis_status == nil or iis_status == ''
      iis_status = 'Not installed'
    end
  end
end