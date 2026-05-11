# frozen_string_literal: true

require 'spec_helper'

describe 'copy_fail' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      context 'with default parameters' do
        it { is_expected.to compile.with_all_deps }

        it {
          is_expected.to contain_file('/etc/modprobe.d/copyfail.conf').with(
            'ensure' => 'file',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0644',
          )
        }

        it { is_expected.to contain_file('/etc/modprobe.d/copyfail.conf').with_content(%r{# Managed by Puppet}) }
        it { is_expected.to contain_file('/etc/modprobe.d/copyfail.conf').without_content(%r{install algif_aead /bin/false}) }
      end

      context 'with mitigate_algif_aead enabled' do
        let(:params) { { 'mitigate_algif_aead' => true } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file('/etc/modprobe.d/copyfail.conf').with_content(%r{install algif_aead /bin/false}) }
      end
    end
  end
end
