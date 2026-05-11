# frozen_string_literal: true

require 'facter'

describe 'copy_fail' do
  before(:each) do
    Facter.clear
    allow(Facter.fact(:kernel)).to receive(:value).and_return('Linux')
    allow(File).to receive(:directory?).and_call_original
    allow(File).to receive(:directory?).with('/etc/modprobe.d').and_return(true)
    allow(File).to receive(:directory?).with('/sys/module/algif_aead').and_return(false)
    allow(File).to receive(:file?).and_call_original
    allow(File).to receive(:read).and_call_original
    allow(File).to receive(:read).with('/proc/cmdline').and_return('')
    allow(Dir).to receive(:glob).and_call_original
    allow(Dir).to receive(:glob).with('/etc/modprobe.d/*').and_return([])
  end

  let(:proc_modules_with_algif) do
    <<~PROC
      algif_aead 16384 0 - Live 0xffffffff00000000
      ip_tables 12345 0 - Live 0xffffffff00000001
    PROC
  end

  let(:proc_modules_without_algif) do
    <<~PROC
      ip_tables 12345 0 - Live 0xffffffff00000000
      nf_conntrack 12345 0 - Live 0xffffffff00000001
    PROC
  end

  let(:modinfo_builtin) { "filename:       (builtin)\ndescription:    AEAD wrapper for AF_ALG\n" }
  let(:modinfo_loadable) { "filename:       /lib/modules/6.5.0/kernel/crypto/algif_aead.ko\n" }

  context 'when algif_aead is a built-in module and active' do
    before(:each) do
      allow(File).to receive(:read).with('/proc/modules').and_return(proc_modules_without_algif)
      allow(File).to receive(:directory?).with('/sys/module/algif_aead').and_return(true)
      allow(Facter::Core::Execution).to receive(:execute)
        .with('modinfo algif_aead', on_fail: :failed)
        .and_return(modinfo_builtin)
    end

    it 'reports type as builtin' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['type']).to eq('builtin')
    end

    it 'reports active as true' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['active']).to be true
    end

    it 'reports loaded as false (built-ins do not appear in /proc/modules)' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['loaded']).to be false
    end

    it 'reports available as true' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['available']).to be true
    end

    it 'reports vulnerable as true' do
      result = Facter.value('copy_fail')
      expect(result['vulnerable']).to be true
    end

    it 'reports mitigated as false' do
      result = Facter.value('copy_fail')
      expect(result['mitigated']).to be false
    end
  end

  context 'when algif_aead is a built-in module but not initialised' do
    before(:each) do
      allow(File).to receive(:read).with('/proc/modules').and_return(proc_modules_without_algif)
      allow(File).to receive(:directory?).with('/sys/module/algif_aead').and_return(false)
      allow(Facter::Core::Execution).to receive(:execute)
        .with('modinfo algif_aead', on_fail: :failed)
        .and_return(modinfo_builtin)
    end

    it 'reports type as builtin' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['type']).to eq('builtin')
    end

    it 'reports active as false' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['active']).to be false
    end

    it 'reports vulnerable as false' do
      result = Facter.value('copy_fail')
      expect(result['vulnerable']).to be false
    end
  end

  context 'when algif_aead is a loadable module and loaded' do
    before(:each) do
      allow(File).to receive(:read).with('/proc/modules').and_return(proc_modules_with_algif)
      allow(Facter::Core::Execution).to receive(:execute)
        .with('modinfo algif_aead', on_fail: :failed)
        .and_return(modinfo_loadable)
    end

    it 'reports type as loadable' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['type']).to eq('loadable')
    end

    it 'reports loaded as true' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['loaded']).to be true
    end

    it 'reports active as true' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['active']).to be true
    end

    it 'reports vulnerable as true' do
      result = Facter.value('copy_fail')
      expect(result['vulnerable']).to be true
    end
  end

  context 'when algif_aead is a loadable module but not loaded' do
    before(:each) do
      allow(File).to receive(:read).with('/proc/modules').and_return(proc_modules_without_algif)
      allow(Facter::Core::Execution).to receive(:execute)
        .with('modinfo algif_aead', on_fail: :failed)
        .and_return(modinfo_loadable)
    end

    it 'reports type as loadable' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['type']).to eq('loadable')
    end

    it 'reports loaded as false' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['loaded']).to be false
    end

    it 'reports active as false' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['active']).to be false
    end

    it 'reports vulnerable as false' do
      result = Facter.value('copy_fail')
      expect(result['vulnerable']).to be false
    end
  end

  context 'when algif_aead is not available at all' do
    before(:each) do
      allow(File).to receive(:read).with('/proc/modules').and_return(proc_modules_without_algif)
      allow(Facter::Core::Execution).to receive(:execute)
        .with('modinfo algif_aead', on_fail: :failed)
        .and_return(:failed)
    end

    it 'reports type as absent' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['type']).to eq('absent')
    end

    it 'reports available as false' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['available']).to be false
    end

    it 'reports vulnerable as false' do
      result = Facter.value('copy_fail')
      expect(result['vulnerable']).to be false
    end

    it 'reports active as false' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['active']).to be false
    end
  end

  context 'when built-in and mitigated via initcall_blacklist' do
    before(:each) do
      allow(File).to receive(:read).with('/proc/modules').and_return(proc_modules_without_algif)
      allow(File).to receive(:directory?).with('/sys/module/algif_aead').and_return(true)
      allow(File).to receive(:read).with('/proc/cmdline')
                                   .and_return("BOOT_IMAGE=/vmlinuz root=/dev/sda1 initcall_blacklist=algif_aead_init quiet\n")
      allow(Facter::Core::Execution).to receive(:execute)
        .with('modinfo algif_aead', on_fail: :failed)
        .and_return(modinfo_builtin)
    end

    it 'reports mitigated as true' do
      result = Facter.value('copy_fail')
      expect(result['mitigated']).to be true
    end

    it 'reports initcall_blacklisted as true' do
      result = Facter.value('copy_fail')
      expect(result['initcall_blacklisted']).to be true
    end

    it 'reports blocked as true' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['blocked']).to be true
    end

    it 'reports reboot_required as true (still active despite mitigation)' do
      result = Facter.value('copy_fail')
      expect(result['reboot_required']).to be true
    end

    it 'reports vulnerable as false (mitigated)' do
      result = Facter.value('copy_fail')
      expect(result['vulnerable']).to be false
    end
  end

  context 'when built-in and initcall_blacklisted and not active (post-reboot)' do
    before(:each) do
      allow(File).to receive(:read).with('/proc/modules').and_return(proc_modules_without_algif)
      allow(File).to receive(:directory?).with('/sys/module/algif_aead').and_return(false)
      allow(File).to receive(:read).with('/proc/cmdline')
                                   .and_return("BOOT_IMAGE=/vmlinuz root=/dev/sda1 initcall_blacklist=algif_aead_init quiet\n")
      allow(Facter::Core::Execution).to receive(:execute)
        .with('modinfo algif_aead', on_fail: :failed)
        .and_return(modinfo_builtin)
    end

    it 'reports mitigated as true' do
      result = Facter.value('copy_fail')
      expect(result['mitigated']).to be true
    end

    it 'reports reboot_required as false' do
      result = Facter.value('copy_fail')
      expect(result['reboot_required']).to be false
    end

    it 'reports active as false' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['active']).to be false
    end
  end

  context 'when loadable and blocked via modprobe.d' do
    before(:each) do
      allow(File).to receive(:read).with('/proc/modules').and_return(proc_modules_with_algif)
      allow(Dir).to receive(:glob).with('/etc/modprobe.d/*').and_return(['/etc/modprobe.d/copyfail.conf'])
      allow(File).to receive(:file?).with('/etc/modprobe.d/copyfail.conf').and_return(true)
      allow(File).to receive(:readlines).with('/etc/modprobe.d/copyfail.conf')
                                        .and_return(["install algif_aead /bin/false\n"])
      allow(Facter::Core::Execution).to receive(:execute)
        .with('modinfo algif_aead', on_fail: :failed)
        .and_return(modinfo_loadable)
    end

    it 'reports blocked as true' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['blocked']).to be true
    end

    it 'reports mitigated as true' do
      result = Facter.value('copy_fail')
      expect(result['mitigated']).to be true
    end

    it 'reports reboot_required as true (still loaded)' do
      result = Facter.value('copy_fail')
      expect(result['reboot_required']).to be true
    end
  end

  context 'when loadable, blocked, and not loaded' do
    before(:each) do
      allow(File).to receive(:read).with('/proc/modules').and_return(proc_modules_without_algif)
      allow(Dir).to receive(:glob).with('/etc/modprobe.d/*').and_return(['/etc/modprobe.d/copyfail.conf'])
      allow(File).to receive(:file?).with('/etc/modprobe.d/copyfail.conf').and_return(true)
      allow(File).to receive(:readlines).with('/etc/modprobe.d/copyfail.conf')
                                        .and_return(["install algif_aead /bin/false\n"])
      allow(Facter::Core::Execution).to receive(:execute)
        .with('modinfo algif_aead', on_fail: :failed)
        .and_return(modinfo_loadable)
    end

    it 'reports reboot_required as false' do
      result = Facter.value('copy_fail')
      expect(result['reboot_required']).to be false
    end

    it 'reports vulnerable as false' do
      result = Facter.value('copy_fail')
      expect(result['vulnerable']).to be false
    end
  end

  context 'when initcall_blacklist contains multiple entries' do
    before(:each) do
      allow(File).to receive(:read).with('/proc/modules').and_return(proc_modules_without_algif)
      allow(File).to receive(:directory?).with('/sys/module/algif_aead').and_return(false)
      allow(File).to receive(:read).with('/proc/cmdline')
                                   .and_return("BOOT_IMAGE=/vmlinuz initcall_blacklist=foo_init,algif_aead_init,bar_init quiet\n")
      allow(Facter::Core::Execution).to receive(:execute)
        .with('modinfo algif_aead', on_fail: :failed)
        .and_return(modinfo_builtin)
    end

    it 'detects algif_aead_init in a comma-separated list' do
      result = Facter.value('copy_fail')
      expect(result['initcall_blacklisted']).to be true
    end
  end

  context 'when /proc/modules is unreadable' do
    before(:each) do
      allow(File).to receive(:read).with('/proc/modules').and_raise(Errno::EACCES, '/proc/modules')
    end

    it 'returns a hash with an error key' do
      result = Facter.value('copy_fail')
      expect(result).to be_a(Hash)
      expect(result).to have_key('error')
      expect(result['error']).to match(%r{Permission denied})
    end
  end

  context 'when /proc/cmdline is unreadable' do
    before(:each) do
      allow(File).to receive(:read).with('/proc/modules').and_return(proc_modules_without_algif)
      allow(File).to receive(:directory?).with('/sys/module/algif_aead').and_return(true)
      allow(File).to receive(:read).with('/proc/cmdline').and_raise(Errno::EACCES, '/proc/cmdline')
      allow(Facter::Core::Execution).to receive(:execute)
        .with('modinfo algif_aead', on_fail: :failed)
        .and_return(modinfo_builtin)
    end

    it 'treats initcall_blacklist as not set' do
      result = Facter.value('copy_fail')
      expect(result['initcall_blacklisted']).to be false
    end

    it 'still reports other fields correctly' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['type']).to eq('builtin')
      expect(result['algif_aead']['active']).to be true
    end
  end

  context 'when kernel is not Linux' do
    before(:each) do
      Facter.clear
      allow(Facter.fact(:kernel)).to receive(:value).and_return('Darwin')
    end

    it 'does not resolve the fact' do
      result = Facter.value('copy_fail')
      expect(result).to be_nil
    end
  end

  context 'when /etc/modprobe.d does not exist' do
    before(:each) do
      allow(File).to receive(:read).with('/proc/modules').and_return(proc_modules_without_algif)
      allow(File).to receive(:directory?).with('/etc/modprobe.d').and_return(false)
      allow(Facter::Core::Execution).to receive(:execute)
        .with('modinfo algif_aead', on_fail: :failed)
        .and_return(modinfo_loadable)
    end

    it 'reports blocked as false' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['blocked']).to be false
    end
  end

  context 'when /proc/modules is empty' do
    before(:each) do
      allow(File).to receive(:read).with('/proc/modules').and_return('')
      allow(Facter::Core::Execution).to receive(:execute)
        .with('modinfo algif_aead', on_fail: :failed)
        .and_return(modinfo_loadable)
    end

    it 'reports loaded as false' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['loaded']).to be false
    end
  end

  context 'when install directive has leading whitespace' do
    before(:each) do
      allow(File).to receive(:read).with('/proc/modules').and_return(proc_modules_without_algif)
      allow(Dir).to receive(:glob).with('/etc/modprobe.d/*').and_return(['/etc/modprobe.d/ws.conf'])
      allow(File).to receive(:file?).with('/etc/modprobe.d/ws.conf').and_return(true)
      allow(File).to receive(:readlines).with('/etc/modprobe.d/ws.conf')
                                        .and_return(["  \tinstall algif_aead /bin/false\n"])
      allow(Facter::Core::Execution).to receive(:execute)
        .with('modinfo algif_aead', on_fail: :failed)
        .and_return(modinfo_loadable)
    end

    it 'detects install directive with leading whitespace' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['blocked']).to be true
    end
  end

  context 'when substring match in /proc/modules (algif_aead_something)' do
    let(:proc_modules_substring) do
      <<~PROC
        algif_aead_extra 16384 0 - Live 0xffffffff00000000
        ip_tables 12345 0 - Live 0xffffffff00000001
      PROC
    end

    before(:each) do
      allow(File).to receive(:read).with('/proc/modules').and_return(proc_modules_substring)
      allow(Facter::Core::Execution).to receive(:execute)
        .with('modinfo algif_aead', on_fail: :failed)
        .and_return(modinfo_loadable)
    end

    it 'does not match algif_aead_extra as algif_aead' do
      result = Facter.value('copy_fail')
      expect(result['algif_aead']['loaded']).to be false
    end
  end
end
