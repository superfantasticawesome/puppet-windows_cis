class windows_cis() {
  # This module applies scored CIS benchmarks, based on 'Profile Applicability' 
  # and recommendations, according to the CIS Windows Server 2012 R2 Benchmark 
  # Guide v2.1.0; including best practices for cloud-based instances. In the 
  # parlance of the aforementioned guide, this module determines 'applicability' 
  # from the value of the Facter fact '$::domain_role'; whose value can be
  # 'domain_controller', 'member_server', or 'standalone_server'.
  # 
  # NOTE: Many of the scored benchmarks are omitted because the target systems 
  # are cloud-based instances where the impact of the control would hinder system 
  # accessibility and/or application performance. References for omitted benchmarks 
  # remain as comments and are included for benchmark consistency and auditing.
  #
  # BEWARE: Thar be Unicorns.
  #
  include windows_cis::tools
  include windows_cis::account_policies
  include windows_cis::audit_policies
  include windows_cis::security_options
  include windows_cis::laps
  include windows_cis::local_group_policy
}
