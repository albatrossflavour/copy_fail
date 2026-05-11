# Changelog

All notable changes to this project will be documented in this file.

## Release 0.1.0

**Features**

- Structured fact (`copy_fail`) detecting CVE-2026-31431 vulnerability status
- Detects built-in vs loadable module type for `algif_aead`
- Checks `/proc/modules`, `/sys/module/`, modprobe.d, and kernel boot parameters
- Reports `vulnerable`, `mitigated`, and `reboot_required` summary keys
- Detects `initcall_blacklist` mitigation for built-in modules
- Detects `install /bin/false` mitigation for loadable modules
