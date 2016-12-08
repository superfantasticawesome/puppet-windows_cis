# Refreshes the Default Domain Policy when LAPS related changes occur
#
class windows_cis::gpupdate {
  exec { 'gpupdate /force':
    path        => $::path,
    refreshonly => true,
    subscribe   => Class['windows_cis::group_policy'],
  }
}