# @summary Detect and mitigate the copy fail kernel vulnerability
#
# @param mitigate_algif_aead
#   Block the algif_aead kernel module via install /bin/false in modprobe.d.
#   Only effective for loadable modules. Built-in modules require
#   initcall_blacklist on the kernel command line instead.
class copy_fail (
  Boolean $mitigate_algif_aead = false,
) {
  file { '/etc/modprobe.d/copyfail.conf':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => epp('copy_fail/copyfail.conf.epp', {
        'mitigate_algif_aead' => $mitigate_algif_aead,
    }),
  }
}
