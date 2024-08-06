require 'spec_helper'

describe 'ds_389' do
  # content blocks
  let(:openssl_ca_cnf) do
    '[ req ]
default_bits = 4096
default_md = sha256
distinguished_name = req_distinguished_name
prompt = no
x509_extensions = v3_ca

[ req_distinguished_name ]
DC = foo.example.com
CN = fooCA

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = CA:true

[ v3_req ]
'
  end

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          networking: { fqdn: 'foo.example.com' },
        )
      end

      context 'without any parameters' do
        it { is_expected.to compile }
        it { is_expected.to contain_class('ds_389::install') }

        it { is_expected.to contain_file('/etc/dirsrv').with_ensure('directory') }

        it {
          is_expected.to contain_exec('Create ldap cacerts directory').with(
            command: 'mkdir -p /etc/openldap/cacerts',
            creates: '/etc/openldap/cacerts',
          )
        }

        it {
          is_expected.to contain_package('389-ds-base').with(
            ensure: 'installed',
          ).that_requires(
            [
              'File[/etc/dirsrv]',
              'Exec[Create ldap cacerts directory]',
            ],
          )
        }

        it {
          is_expected.to contain_group('dirsrv').with(
            ensure: 'present',
            system: true,
          )
        }

        case os_facts[:osfamily]
        when 'Debian'
          it {
            is_expected.to contain_package('libnss3-tools').with(
              ensure: 'present',
            )
          }

          it {
            is_expected.to contain_user('dirsrv').with(
              ensure: 'present',
              system: true,
              home: '/usr/share/dirsrv',
              shell: '/bin/false',
              gid: 'dirsrv',
            ).that_requires('Group[dirsrv]')
          }

          it {
            is_expected.not_to contain_package('389-ds').with(
              provider: 'dnfmodule',
            )
          }

          it {
            is_expected.to contain_ini_setting('dirsrv ulimit').with(
              ensure: 'present',
              path: '/etc/default/dirsrv.systemd',
              section: 'Service',
              setting: 'LimitNOFILE',
              value: '8192',
            ).that_requires('Package[389-ds-base]')
          }

        when 'RedHat'
          it {
            is_expected.to contain_package('nss-tools').with(
              ensure: 'present',
            )
          }

          it {
            is_expected.to contain_user('dirsrv').with(
              ensure: 'present',
              system: true,
              home: '/usr/share/dirsrv',
              shell: '/sbin/nologin',
              gid: 'dirsrv',
            ).that_requires('Group[dirsrv]')
          }

          case os_facts[:operatingsystemmajrelease]
          when '8'
            it {
              is_expected.to contain_package('389-ds').with(
                ensure: '1.4',
                enable_only: 'true',
                provider: 'dnfmodule',
              )
            }
          end

          it {
            is_expected.to contain_ini_setting('dirsrv ulimit').with(
              ensure: 'present',
              path: '/etc/sysconfig/dirsrv.systemd',
              section: 'Service',
              setting: 'LimitNOFILE',
              value: '8192',
            ).that_requires('Package[389-ds-base]')
          }
        end
      end

      context 'with parameter overrides' do
        let(:params) do
          {
            package_name: '389-ds-custom',
            user: 'custom_user',
            group: 'custom_group',
            cacerts_path: '/custom/cacerts/path',
            home_dir: '/custom/home/path',
          }
        end

        it { is_expected.to compile }
        it { is_expected.to contain_class('ds_389::install') }

        it {
          is_expected.to contain_exec('Create ldap cacerts directory').with(
            command: 'mkdir -p /custom/cacerts/path',
            creates: '/custom/cacerts/path',
          )
        }

        it {
          is_expected.to contain_package('389-ds-custom').with(
            ensure: 'installed',
          ).that_requires(
            [
              'File[/etc/dirsrv]',
              'Exec[Create ldap cacerts directory]',
            ],
          )
        }

        it {
          is_expected.to contain_group('custom_group').with(
            ensure: 'present',
            system: true,
          )
        }
        case os_facts[:osfamily]
        when 'Debian'
          it {
            is_expected.to contain_user('custom_user').with(
              ensure: 'present',
              system: true,
              home: '/custom/home/path',
              shell: '/bin/false',
              gid: 'custom_group',
            ).that_requires('Group[custom_group]')
          }
        when 'RedHat'
          it {
            is_expected.to contain_user('custom_user').with(
              ensure: 'present',
              system: true,
              home: '/custom/home/path',
              shell: '/sbin/nologin',
              gid: 'custom_group',
            ).that_requires('Group[custom_group]')
          }
        end
      end

      context 'when declaring an instance' do
        let(:params) do
          {
            instances: {
              'foo' => {
                'root_dn'      => 'cn=Directory Manager',
                'root_dn_pass' => 'supersecret',
                'suffix'       => 'dc=example,dc=com',
                'cert_db_pass' => 'secret',
                'server_id'    => 'foo',
              },
            },
          }
        end

        it { is_expected.to compile }

        it { is_expected.to contain_ds_389__instance('foo') }
        it { is_expected.to contain_ds_389__service('foo') }
        it { is_expected.to contain_ds_389__ssl('foo') }
        it { is_expected.to contain_exec('Clean up temp passwd file: foo') }
        it { is_expected.to contain_exec('Clean up temp noise file: foo') }
        it { is_expected.to contain_exec('Create cert DB: foo') }
        it { is_expected.to contain_exec('Export CA cert: foo') }
        it { is_expected.to contain_exec('Export server cert: foo') }
        it { is_expected.to contain_ssl_pkey('Generate CA private key: foo') }
        it { is_expected.to contain_exec('Generate noise file: foo') }
        it { is_expected.to contain_exec('Generate password file: foo') }
        it { is_expected.to contain_exec('Import ssl ldif: foo') }

        it {
          is_expected.to contain_file('Create CA config: foo').with(
            ensure: 'file',
            content: openssl_ca_cnf,
          )
        }
        it { is_expected.to contain_x509_cert('Create CA cert: foo') }
        it { is_expected.to contain_exec('Prepare CA cert for import (pkcs12): foo') }
        it { is_expected.to contain_exec('Import CA cert: foo') }
        it { is_expected.to contain_exec('Fix name of imported CA: foo') }
        it { is_expected.to contain_exec('Add trust for CA: foo') }

        it { is_expected.to contain_exec('Make server cert and add to database: foo') }
        it { is_expected.to contain_exec('Add trust for server cert: foo') }

        it { is_expected.to contain_exec('Rehash cacertdir: foo') }
        it { is_expected.to contain_exec('Restart foo to enable SSL') }
        it { is_expected.to contain_exec('Set permissions on database directory: foo') }
        it { is_expected.to contain_exec('restart foo to pick up new token') }
        it { is_expected.to contain_exec('setup ds: foo') }
        it { is_expected.to contain_exec('stop foo to create new token') }
        it { is_expected.to contain_file('/etc/dirsrv/slapd-foo/pin.txt') }
        it { is_expected.to contain_file('/etc/dirsrv/slapd-foo/ssl.ldif') }
        it { is_expected.to contain_file('/etc/openldap/cacerts/fooCA.pem') }
        it { is_expected.to contain_file('/etc/openldap/cacerts/fooCert.pem') }
        case os_facts[:operatingsystemmajrelease]
        when '6', '14.04'
          it { is_expected.to contain_file('/etc/init.d/dirsrv@foo') }
        end
        it { is_expected.to contain_service('dirsrv@foo') }
      end
    end
  end
end
