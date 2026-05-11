# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.1] - 2026-05-11

### Added

- Amazon Linux 2 and 2023 to supported operating systems

## [1.0.0] - 2026-05-11

### Added

- Puppet class (`copy_fail`) with opt-in parameter (`mitigate_algif_aead`) to block vulnerable module via `install /bin/false` in `/etc/modprobe.d/copyfail.conf`
- Bolt task (`copy_fail::unload`) to immediately unload algif_aead kernel module via `modprobe -r`
- `initcall_blacklist` detection for built-in module mitigation
- Comprehensive README with vulnerability context (CVE-2026-31431), usage examples, PuppetDB queries, and limitations
- REFERENCE.md generated from Puppet Strings

## [0.1.0] - 2026-05-10

### Added

- Structured fact (`copy_fail`) detecting CVE-2026-31431 vulnerability status
- Detects built-in vs loadable module type for `algif_aead`
- Checks `/proc/modules`, `/sys/module/`, modprobe.d, and kernel boot parameters
- Reports `vulnerable`, `mitigated`, and `reboot_required` summary keys
- Detects `initcall_blacklist` mitigation for built-in modules
- Detects `install /bin/false` mitigation for loadable modules
