# copy_fail

Detect the [Copy Fail](https://nvd.nist.gov/vuln/detail/CVE-2026-31431) kernel vulnerability across your Linux fleet.

## What is Copy Fail?

Copy Fail ([CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)) is a Linux kernel vulnerability in the AF_ALG subsystem's AEAD interface. Attackers can exploit the `algif_aead` kernel module to achieve local privilege escalation. Unlike many kernel module vulnerabilities, `algif_aead` is compiled as a **built-in** module on most major distributions, which changes the mitigation approach significantly.

The primary mitigation depends on how the module is compiled:

- **Built-in** (most distros): Add `initcall_blacklist=algif_aead_init` to kernel boot parameters and reboot. The `install /bin/false` approach does not work for built-in modules.
- **Loadable** (some custom kernels): Block via `install algif_aead /bin/false` in `/etc/modprobe.d/`, same as other module-blocking mitigations.

## What this module provides

This module ships a structured fact (`copy_fail`) that reports vulnerability status, module type (built-in vs loadable), active mitigation state, and whether a reboot is needed. No code changes required, just deploy the module.

The fact is the primary tool. Deploy the module and you get fleet-wide visibility without touching a manifest.

## Setup

### Requirements

- Puppet 7.x or 8.x
- Linux operating system

### Supported operating systems

- RedHat 7, 8, 9
- CentOS 7, 8
- Ubuntu 20.04, 22.04, 24.04
- Debian 11, 12
- SLES 15

## The copy_fail fact

Once the module is deployed, the `copy_fail` fact is available on every Linux node automatically. No class inclusion is needed.

### Fact structure

The fact returns a hash with module detail and summary keys:

```json
{
  "algif_aead": {
    "type": "builtin",
    "loaded": false,
    "active": true,
    "blocked": false,
    "available": true
  },
  "initcall_blacklisted": false,
  "vulnerable": true,
  "mitigated": false,
  "reboot_required": false
}
```

#### Module keys

| Key | Type | Meaning |
| --- | --- | --- |
| `type` | String | How the module is compiled: `builtin`, `loadable`, or `absent` |
| `loaded` | Boolean | Module appears in `/proc/modules` (always `false` for built-in modules) |
| `active` | Boolean | Module is active in the kernel. For built-in modules, checks `/sys/module/`. For loadable modules, checks `/proc/modules` |
| `blocked` | Boolean | An `install /bin/false` directive exists in `/etc/modprobe.d/` **or** the module is in the kernel `initcall_blacklist` |
| `available` | Boolean | Module exists on the system (`modinfo` can find it) |

#### Summary keys

| Key | Type | Meaning |
| --- | --- | --- |
| `initcall_blacklisted` | Boolean | `algif_aead_init` appears in the kernel boot parameter `initcall_blacklist` |
| `vulnerable` | Boolean | `true` if the module is active and not mitigated |
| `mitigated` | Boolean | `true` if the appropriate mitigation is in place (initcall blacklist for built-in, modprobe.d block for loadable) |
| `reboot_required` | Boolean | `true` if mitigation is applied but the module is still active (reboot needed to take effect) |

### Why type matters

The `type` field tells you which mitigation path applies:

- **`builtin`**: The module is compiled into the kernel. `install /bin/false` in modprobe.d has no effect. Use `initcall_blacklist=algif_aead_init` as a kernel boot parameter instead.
- **`loadable`**: The module is a `.ko` file loaded on demand. `install algif_aead /bin/false` in modprobe.d will prevent it from loading.
- **`absent`**: The module does not exist on this system. The node is not vulnerable to this specific exploit.

### Querying the fact

On a single node:

```shell
puppet facts show copy_fail
```

### Accessing the fact in Puppet code

The fact is available as `$facts['copy_fail']` in any manifest or profile:

```puppet
if $facts['copy_fail']['vulnerable'] {
  notify { 'copy_fail_vulnerable':
    message  => 'This node is vulnerable to Copy Fail (CVE-2026-31431)',
    loglevel => warning,
  }
}

if $facts['copy_fail']['reboot_required'] {
  notify { 'copy_fail_reboot':
    message  => 'Reboot required to complete Copy Fail mitigation',
    loglevel => warning,
  }
}
```

### PuppetDB queries

Find all vulnerable nodes:

```shell
puppet query 'facts[certname, value] { name = "copy_fail" and value.vulnerable = true }'
```

Find nodes that need a reboot to complete mitigation:

```shell
puppet query 'facts[certname, value] { name = "copy_fail" and value.reboot_required = true }'
```

Find nodes where algif_aead is built-in (most common case):

```shell
puppet query 'facts[certname, value] { name = "copy_fail" and value.algif_aead.type = "builtin" }'
```

Find nodes where the initcall blacklist is applied:

```shell
puppet query 'facts[certname, value] { name = "copy_fail" and value.initcall_blacklisted = true }'
```

## What this module affects

This module only reads system state. No files are written.

- Reads `/proc/modules` for loaded module state
- Reads `/sys/module/algif_aead` for built-in module active state
- Scans `/etc/modprobe.d/` files for `install /bin/false` directives
- Reads `/proc/cmdline` for `initcall_blacklist` boot parameters
- Runs `modinfo algif_aead` to determine module type

## Limitations

- **Linux only.** The fact is confined to nodes where `kernel == 'Linux'`.
- **Detection only.** This version does not include a class to manage mitigations. Mitigation management (GRUB boot parameters for built-in modules, modprobe.d for loadable modules) is planned for a future release.
- **No kernel version detection.** The module reports module state regardless of kernel version. If you need kernel-version-aware logic, handle that in your classification or Hiera hierarchy.

## Reference

Full reference documentation is available in [REFERENCE.md](REFERENCE.md), generated from inline Puppet Strings comments.

## Development

This module uses the [Puppet Development Kit (PDK)](https://www.puppet.com/docs/pdk/latest/pdk.html).

Validate the module:

```shell
pdk validate
```

Run unit tests:

```shell
pdk test unit
```

Run a specific test file:

```shell
pdk test unit --tests spec/unit/facter/copy_fail_spec.rb
```
