# copy_fail

Detect and mitigate the [Copy Fail](https://nvd.nist.gov/vuln/detail/CVE-2026-31431) kernel vulnerability across your Linux fleet.

## What is Copy Fail?

Copy Fail ([CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)) is a Linux kernel vulnerability in the AF_ALG subsystem's AEAD interface. Attackers can exploit the `algif_aead` kernel module to achieve local privilege escalation. Unlike many kernel module vulnerabilities, `algif_aead` is compiled as a **built-in** module on most major distributions, which changes the mitigation approach significantly.

The mitigation depends on how the module is compiled:

- **Built-in** (most distros): Add `initcall_blacklist=algif_aead_init` to kernel boot parameters and reboot. The `install /bin/false` approach does not work for built-in modules.
- **Loadable** (some custom kernels): Block via `install algif_aead /bin/false` in `/etc/modprobe.d/`, same as other module-blocking mitigations.

## What this module provides

This module ships three complementary tools:

1. **A structured fact** (`copy_fail`) that reports vulnerability status, module type (built-in vs loadable), active mitigation state, and whether a reboot is needed. No code changes required, just deploy the module.
2. **A Puppet class** (`copy_fail`) that persistently blocks `algif_aead` via an `install /bin/false` directive in `/etc/modprobe.d/copyfail.conf`. Only effective for loadable modules.
3. **A task** (`copy_fail::unload`) that immediately unloads the module from a running kernel (loadable modules only).

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

- **`builtin`**: The module is compiled into the kernel. `install /bin/false` in modprobe.d has no effect. Use `initcall_blacklist=algif_aead_init` as a kernel boot parameter instead. This module cannot automate that change (see [Limitations](#limitations)).
- **`loadable`**: The module is a `.ko` file loaded on demand. The `copy_fail` class and `install algif_aead /bin/false` in modprobe.d will prevent it from loading.
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

## The copy_fail class (optional)

The class manages `/etc/modprobe.d/copyfail.conf`. When `mitigate_algif_aead` is set to `true`, it writes an `install algif_aead /bin/false` directive that persistently prevents the module from loading on boot or via explicit `modprobe` calls.

This only works for loadable modules. If your servers report `type: builtin`, the class will have no effect and you need `initcall_blacklist` on the kernel command line instead (see [Why type matters](#why-type-matters)).

Only include this class when you need Puppet to enforce the block. The fact works independently.

If you include the class with the parameter left at its default (`false`), the config file is still created but contains no `install` directive.

### Parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `mitigate_algif_aead` | `Boolean` | `false` | Block the `algif_aead` kernel module via `install /bin/false` |

### Usage with Hiera

```yaml
copy_fail::mitigate_algif_aead: true
```

Then classify the node:

```puppet
include copy_fail
```

### Usage with resource-like declaration

```puppet
class { 'copy_fail':
  mitigate_algif_aead => true,
}
```

### Why install /bin/false instead of a blacklist directive?

A `blacklist` directive only prevents autoloading. It does not block explicit `modprobe` calls. The `install ... /bin/false` approach ensures the module cannot be loaded by any mechanism, which is why this module uses it.

## The unload task

The `copy_fail::unload` task unloads the `algif_aead` module from the running kernel immediately, without waiting for a reboot.

```shell
puppet task run copy_fail::unload module=algif_aead --nodes servers
```

On success:

```json
{
  "module": "algif_aead",
  "status": "unloaded",
  "message": "Successfully unloaded module 'algif_aead'"
}
```

The task returns an error if the module is not currently loaded, is in use by another kernel subsystem, or is not in the allow-list. If a module is in use and cannot be unloaded, apply the block and reboot.

This task only works for loadable modules. Built-in modules cannot be unloaded.

## What this module affects

- **Fact only (no class):** reads `/proc/modules`, `/sys/module/algif_aead`, `/proc/cmdline`, scans `/etc/modprobe.d/` files, and runs `modinfo`. No files are written.
- **Class included:** creates and manages `/etc/modprobe.d/copyfail.conf` (owned by `root:root`, mode `0644`). The file is present whenever the class is included, even if the parameter is `false`.
- **Task:** runs `modprobe -r` to unload the module from the running kernel.

## Mitigating built-in modules

When `algif_aead` is compiled into the kernel (which is the common case on stock distribution kernels), the modprobe.d approach has no effect. The module's init function runs at boot before modprobe is involved.

To mitigate a built-in `algif_aead`:

1. Add `initcall_blacklist=algif_aead_init` to your kernel boot parameters (typically via GRUB configuration)
2. Reboot the server

On RHEL/CentOS, edit `/etc/default/grub` and add it to `GRUB_CMDLINE_LINUX`, then run `grub2-mkconfig -o /boot/grub2/grub.cfg`.

On Ubuntu/Debian, edit `/etc/default/grub` and add it to `GRUB_CMDLINE_LINUX_DEFAULT`, then run `update-grub`.

This module does not automate GRUB changes because getting boot configuration wrong can render a system unbootable. You can manage your GRUB configuration with Puppet (for example, using `file_line` or an `augeas` resource to set kernel parameters), but doing so is out of scope for this module. The fact will report `initcall_blacklisted: true` once the parameter is in place, and `reboot_required: true` until the reboot completes.

## Limitations

- **Linux only.** The fact is confined to nodes where `kernel == 'Linux'`. The class and task assume Linux kernel module tooling.
- **Loadable modules only for class and task.** The class writes `modprobe.d` configuration that only affects loadable modules. Built-in modules require `initcall_blacklist` on the kernel command line, which this module does not manage (see [Mitigating built-in modules](#mitigating-built-in-modules)).
- **Blocking does not unload live modules.** The class writes `modprobe.d` configuration that takes effect on next boot or next `modprobe` call. Use the task or a reboot to remove already-loaded modules.
- **No kernel version detection.** The module reports module state regardless of kernel version. If you need kernel-version-aware logic, handle that in your classification or Hiera hierarchy.
- **Module in use.** The task cannot unload a module that is in use by another kernel subsystem. Apply the block and reboot in that case.

## Reference

Full reference documentation for classes and tasks is available in [REFERENCE.md](REFERENCE.md), generated from inline Puppet Strings comments.

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

Generate REFERENCE.md:

```shell
pdk bundle exec puppet strings generate --format markdown
```
