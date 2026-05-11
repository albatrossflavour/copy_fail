# frozen_string_literal: true

Facter.add('copy_fail') do
  confine kernel: 'Linux'

  setcode do
    mod = 'algif_aead'

    begin
      proc_modules_content = File.read('/proc/modules')
      loaded_modules = proc_modules_content.each_line.map { |line| line.split.first }.compact
    rescue StandardError => e
      next { 'error' => "Failed to read /proc/modules: #{e.message}" }
    end

    loaded = loaded_modules.include?(mod)

    modinfo_output = Facter::Core::Execution.execute("modinfo #{mod}", on_fail: :failed)
    available = modinfo_output != :failed
    builtin = available && modinfo_output.to_s.match?(%r{filename:\s+\(builtin\)})

    sys_module_present = File.directory?("/sys/module/#{mod}")

    if builtin
      mod_type = 'builtin'
      active = sys_module_present
    elsif available
      mod_type = 'loadable'
      active = loaded
    else
      mod_type = 'absent'
      active = false
    end

    blocked_modprobe = false
    modprobe_dir = '/etc/modprobe.d'
    if File.directory?(modprobe_dir)
      begin
        Dir.glob(File.join(modprobe_dir, '*')).each do |conf_file|
          next unless File.file?(conf_file)

          File.readlines(conf_file).each do |line|
            if line.match?(%r{^\s*install\s+#{Regexp.escape(mod)}\s+/bin/(true|false)})
              blocked_modprobe = true
              break
            end
          end
          break if blocked_modprobe
        end
      rescue StandardError
        # If we cannot read modprobe.d files, treat as not blocked
      end
    end

    blocked_initcall = false
    begin
      cmdline = File.read('/proc/cmdline')
      blocked_initcall = cmdline.match?(%r{(?:^|\s)initcall_blacklist=[^\s]*#{Regexp.escape(mod)}_init})
    rescue StandardError
      # If we cannot read /proc/cmdline, treat as not blocked
    end

    mitigated = if builtin
                  blocked_initcall
                else
                  blocked_modprobe
                end

    reboot_required = mitigated && active

    {
      mod => {
        'type'      => mod_type,
        'loaded'    => loaded,
        'active'    => active,
        'blocked'   => blocked_modprobe || blocked_initcall,
        'available' => available,
      },
      'initcall_blacklisted' => blocked_initcall,
      'vulnerable'           => active && !mitigated,
      'mitigated'            => mitigated,
      'reboot_required'      => reboot_required,
    }
  end
end
