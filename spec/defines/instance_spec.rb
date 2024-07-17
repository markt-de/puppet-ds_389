require 'spec_helper'

describe 'ds_389::instance' do
  let(:pre_condition) do
    'class {"::ds_389": }'
  end
  let(:title) { 'specdirectory' }

  on_supported_os(facterversion: '2.4').each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          networking: { fqdn: 'foo.example.com' },
        )
      end

      context 'with required params' do
        let(:params) do
          {
            root_dn: 'cn=Directory Manager',
            suffix: 'dc=example,dc=com',
            cert_db_pass: 'secret',
            root_dn_pass: 'supersecure',
            server_id: 'specdirectory',
          }
        end

        it { is_expected.to compile }

        it {
          is_expected.to contain_file('/etc/dirsrv/slapd-specdirectory/pin.txt').with(
            ensure: 'file',
            mode: '0440',
            owner: 'dirsrv',
            group: 'dirsrv',
            content: "Internal (Software) Token:supersecure\n",
          ).that_requires('Exec[setup ds: specdirectory]').that_notifies(
            'Exec[restart specdirectory to pick up new token]',
          )
        }

        it {
          is_expected.to contain_exec('Rehash cacertdir: specdirectory').with(
            command: 'openssl rehash /etc/openldap/cacerts',
            path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            refreshonly: true,
          )
        }

        case os_facts[:kernel]
        when 'Linux'
          it {
            is_expected.to contain_exec('setup ds: specdirectory').with(
              command: 'dscreate from-file /etc/dirsrv/template-specdirectory.inf',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              creates: '/etc/dirsrv/slapd-specdirectory',
            )
          }

          it {
            is_expected.to contain_exec('stop specdirectory to create new token').with(
              command: 'systemctl stop dirsrv@specdirectory ; sleep 2',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              refreshonly: true,
            ).that_comes_before('File[/etc/dirsrv/slapd-specdirectory/pin.txt]')
          }

          it {
            is_expected.to contain_exec('restart specdirectory to pick up new token').with(
              command: 'systemctl restart dirsrv@specdirectory ; sleep 2',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              refreshonly: true,
            )
          }
        else
          it {
            is_expected.to contain_exec('stop specdirectory to create new token').with(
              command: 'service dirsrv stop specdirectory ; sleep 2',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              refreshonly: true,
            ).that_comes_before('File[/etc/dirsrv/slapd-specdirectory/pin.txt]')
          }

          it {
            is_expected.to contain_exec('restart specdirectory to pick up new token').with(
              command: 'service dirsrv restart specdirectory ; sleep 2',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              refreshonly: true,
            )
          }
        end

        it {
          is_expected.to contain_exec('Generate noise file: specdirectory').with(
            command: %r{echo \d+ | sha256sum | awk '{print $1}' > /tmp/noisefile-specdirectory},
            path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            refreshonly: true,
          ).that_subscribes_to('Exec[stop specdirectory to create new token]')
        }

        it {
          is_expected.to contain_exec('Generate password file: specdirectory').with(
            command: 'echo supersecure > /tmp/passfile-specdirectory',
            path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            refreshonly: true,
          ).that_subscribes_to('Exec[Create cert DB: specdirectory]')
        }

        it {
          is_expected.to contain_exec('Create cert DB: specdirectory').with(
            command: 'certutil -N -d /etc/dirsrv/slapd-specdirectory -f /tmp/passfile-specdirectory',
            path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            refreshonly: true,
          ).that_notifies('Ssl_pkey[Generate CA private key: specdirectory]')
        }

        it {
          is_expected.to contain_ssl_pkey('Generate CA private key: specdirectory').with(
            size: 4096,
          )
        }

        it {
          is_expected.to contain_x509_cert('Create CA cert: specdirectory').with(
            days: 3650,
            req_ext: false,
          )
        }

        it {
          is_expected.to contain_exec('Add trust for CA: specdirectory').with(
            command: 'certutil -M -n "specdirectoryCA" -t CT,C,C -d /etc/dirsrv/slapd-specdirectory -f /tmp/passfile-specdirectory',
            path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            unless: 'certutil -L -d /etc/dirsrv/slapd-specdirectory | grep "specdirectoryCA" | grep "CTu,Cu,Cu"',
          ).that_notifies('Exec[Export CA cert: specdirectory]')
        }

        it {
          is_expected.to contain_exec('Make server cert and add to database: specdirectory').with(
            cwd: '/etc/dirsrv/slapd-specdirectory',
            command: 'certutil -S -n "specdirectoryCert" -m 101 -s "cn=foo.example.com" -c "specdirectoryCA" -t "u,u,u" -v 120 -d /etc/dirsrv/slapd-specdirectory -k rsa -z /tmp/noisefile-specdirectory -f /tmp/passfile-specdirectory  && sleep 2', # rubocop:disable LineLength
            path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            refreshonly: true,
          ).that_notifies(
            [
              'Exec[Set permissions on database directory: specdirectory]',
              'Exec[Clean up temp noise file: specdirectory]',
              'Exec[Clean up temp passwd file: specdirectory]',
              'Exec[Add trust for server cert: specdirectory]',
            ],
          )
        }

        it {
          is_expected.to contain_exec('Add trust for server cert: specdirectory').with(
            command: 'certutil -M -n "specdirectoryCert" -t u,u,u -d /etc/dirsrv/slapd-specdirectory',
            path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            unless: 'certutil -L -d /etc/dirsrv/slapd-specdirectory | grep "specdirectoryCert" | grep "u,u,u"',
          ).that_notifies('Exec[Export server cert: specdirectory]')
        }

        it {
          is_expected.to contain_exec('Set permissions on database directory: specdirectory').with(
            command: 'chown dirsrv:dirsrv /etc/dirsrv/slapd-specdirectory',
            refreshonly: true,
          )
        }

        it {
          is_expected.to contain_exec('Export CA cert: specdirectory').with(
            cwd: '/etc/dirsrv/slapd-specdirectory',
            command: 'certutil -d /etc/dirsrv/slapd-specdirectory -L -n "specdirectoryCA" -a > /etc/dirsrv/slapd-specdirectory/specdirectoryCA.pem',
            path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            creates: '/etc/dirsrv/slapd-specdirectory/specdirectoryCA.pem',
          )
        }

        it {
          is_expected.to contain_file('/etc/openldap/cacerts/specdirectoryCA.pem').with(
            ensure: 'file',
            source: '/etc/dirsrv/slapd-specdirectory/specdirectoryCA.pem',
          ).that_requires('Exec[Export CA cert: specdirectory]').that_notifies(
            'Exec[Rehash cacertdir: specdirectory]',
          )
        }

        it {
          is_expected.to contain_exec('Clean up temp passwd file: specdirectory').with(
            command: 'rm -f /tmp/passfile-specdirectory',
            refreshonly: true,
          )
        }

        it {
          is_expected.to contain_exec('Clean up temp noise file: specdirectory').with(
            command: 'rm -f /tmp/noisefile-specdirectory',
            refreshonly: true,
          )
        }

        it {
          is_expected.to contain_exec('Export server cert: specdirectory').with(
            cwd: '/etc/dirsrv/slapd-specdirectory',
            command: 'certutil -d /etc/dirsrv/slapd-specdirectory -L -n "specdirectoryCert" -a > specdirectoryCert.pem',
            path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            creates: '/etc/dirsrv/slapd-specdirectory/specdirectoryCert.pem',
          )
        }

        it {
          is_expected.to contain_file('/etc/openldap/cacerts/specdirectoryCert.pem').with(
            ensure: 'file',
            source: '/etc/dirsrv/slapd-specdirectory/specdirectoryCert.pem',
          ).that_requires('Exec[Export server cert: specdirectory]').that_notifies(
            'Exec[Rehash cacertdir: specdirectory]',
          )
        }

        it {
          is_expected.to contain_ds_389__ssl('specdirectory').with(
            cert_name: 'specdirectoryCert',
            root_dn: 'cn=Directory Manager',
            root_dn_pass: 'supersecure',
            server_host: 'foo.example.com',
            server_port: 389,
            user: 'dirsrv',
            group: 'dirsrv',
            minssf: 0,
            ssl_version_min: 'TLS1.1',
          )
        }

        it { is_expected.to contain_ds_389__service('specdirectory') }

        it { is_expected.not_to contain_concat__fragment('specdirectory_cert') }
        it { is_expected.not_to contain_concat__fragment('specdirectory_ca_bundle') }
        it { is_expected.not_to contain_concat__fragment('specdirectory_key') }
        it { is_expected.not_to contain_concat('specdirectory_cert_bundle') }
        it { is_expected.not_to contain_exec('Create pkcs12 cert: specdirectory') }
        it { is_expected.not_to contain_exec('Add trust for CA0: specdirectory') }
        it { is_expected.not_to contain_exec('Export CA cert 0: specdirectory') }
        it { is_expected.not_to contain_file('/etc/openldap/cacerts/specdirectoryCA0.pem') }

        context 'when importing an external ssl cert bundle' do
          let(:params) do
            {
              root_dn: 'cn=Directory Manager',
              suffix: 'dc=example,dc=com',
              cert_db_pass: 'secret',
              root_dn_pass: 'supersecure',
              server_id: 'specdirectory',
              ssl: {
                'cert_path' => 'puppet:///specfiles/ssl_cert.pem',
                'key_path' => 'puppet:///specfiles/ssl_key.pem',
                'ca_bundle_path' => 'puppet:///specfiles/ssl_ca.pem',
                'ca_cert_names' => [
                  'Spec Intermediate Certificate',
                  'Spec Root Certificate',
                ],
                'cert_name' => 'Spec Certificate',
              },
            }
          end

          it { is_expected.to compile }

          it {
            is_expected.to contain_exec('Clean up temp passwd file: specdirectory').with(
              command: 'rm -f /tmp/passfile-specdirectory',
              refreshonly: true,
            )
          }

          it {
            is_expected.to contain_concat__fragment('specdirectory_cert').with(
              target: 'specdirectory_cert_bundle',
              source: 'puppet:///specfiles/ssl_cert.pem',
              order: '0',
            )
          }
          it {
            is_expected.to contain_concat__fragment('specdirectory_ca_bundle').with(
              target: 'specdirectory_cert_bundle',
              source: 'puppet:///specfiles/ssl_ca.pem',
              order: '1',
            )
          }
          it {
            is_expected.to contain_concat__fragment('specdirectory_key').with(
              target: 'specdirectory_cert_bundle',
              source: 'puppet:///specfiles/ssl_key.pem',
              order: '2',
            )
          }

          case os_facts[:osfamily]
          when 'Debian'
            it {
              is_expected.to contain_concat('specdirectory_cert_bundle').with(
                mode: '0600',
                path: '/etc/ssl/specdirectory-bundle.pem',
              ).that_notifies('Exec[Create pkcs12 cert: specdirectory]')
            }
            it {
              is_expected.to contain_exec('Create pkcs12 cert: specdirectory').with(
                command: 'openssl pkcs12 -export -password pass:secret -name foo.example.com -in /etc/ssl/specdirectory-bundle.pem -out /etc/ssl/specdirectory.p12',
                path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
                refreshonly: true,
              ).that_notifies('Exec[Create cert DB: specdirectory]')
            }
            it {
              is_expected.to contain_exec('Create cert DB: specdirectory').with(
                command: 'pk12util -i /etc/ssl/specdirectory.p12 -d /etc/dirsrv/slapd-specdirectory -W secret -K supersecure',
                path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
                refreshonly: true,
              )
            }
          when 'RedHat'
            it {
              is_expected.to contain_concat('specdirectory_cert_bundle').with(
                mode: '0600',
                path: '/etc/pki/tls/certs/specdirectory-bundle.pem',
              ).that_notifies('Exec[Create pkcs12 cert: specdirectory]')
            }
            it {
              is_expected.to contain_exec('Create pkcs12 cert: specdirectory').with(
                command: 'openssl pkcs12 -export -password pass:secret -name foo.example.com -in /etc/pki/tls/certs/specdirectory-bundle.pem -out /etc/pki/tls/certs/specdirectory.p12',
                path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
                refreshonly: true,
              ).that_notifies('Exec[Create cert DB: specdirectory]')
            }
            it {
              is_expected.to contain_exec('Create cert DB: specdirectory').with(
                command: 'pk12util -i /etc/pki/tls/certs/specdirectory.p12 -d /etc/dirsrv/slapd-specdirectory -W secret -K supersecure',
                path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
                refreshonly: true,
              )
            }
          end

          it {
            is_expected.to contain_exec('Add trust for CA0: specdirectory').with(
              command: 'certutil -M -n "Spec Intermediate Certificate" -t CT,, -d /etc/dirsrv/slapd-specdirectory -f /tmp/passfile-specdirectory',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              unless: 'certutil -L -d /etc/dirsrv/slapd-specdirectory | grep "Spec Intermediate Certificate" | grep "CT"',
            ).that_requires('Exec[Create cert DB: specdirectory]').that_notifies('Exec[Export CA cert 0: specdirectory]')
          }
          it {
            is_expected.to contain_exec('Export CA cert 0: specdirectory').with(
              cwd: '/etc/dirsrv/slapd-specdirectory',
              command: 'certutil -d /etc/dirsrv/slapd-specdirectory -L -n "Spec Intermediate Certificate" -a > specdirectoryCA0.pem',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              creates: '/etc/dirsrv/slapd-specdirectory/specdirectoryCA0.pem',
            )
          }
          it {
            is_expected.to contain_file('/etc/openldap/cacerts/specdirectoryCA0.pem').with(
              ensure: 'file',
              source: '/etc/dirsrv/slapd-specdirectory/specdirectoryCA0.pem',
            ).that_requires('Exec[Export CA cert 0: specdirectory]').that_notifies('Exec[Rehash cacertdir: specdirectory]')
          }

          it {
            is_expected.to contain_exec('Add trust for CA1: specdirectory').with(
              command: 'certutil -M -n "Spec Root Certificate" -t CT,, -d /etc/dirsrv/slapd-specdirectory -f /tmp/passfile-specdirectory',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              unless: 'certutil -L -d /etc/dirsrv/slapd-specdirectory | grep "Spec Root Certificate" | grep "CT"',
            ).that_requires('Exec[Create cert DB: specdirectory]').that_notifies('Exec[Export CA cert 1: specdirectory]')
          }
          it {
            is_expected.to contain_exec('Export CA cert 1: specdirectory').with(
              cwd: '/etc/dirsrv/slapd-specdirectory',
              command: 'certutil -d /etc/dirsrv/slapd-specdirectory -L -n "Spec Root Certificate" -a > specdirectoryCA1.pem',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              creates: '/etc/dirsrv/slapd-specdirectory/specdirectoryCA1.pem',
            )
          }
          it {
            is_expected.to contain_file('/etc/openldap/cacerts/specdirectoryCA1.pem').with(
              ensure: 'file',
              source: '/etc/dirsrv/slapd-specdirectory/specdirectoryCA1.pem',
            ).that_requires('Exec[Export CA cert 1: specdirectory]').that_notifies('Exec[Rehash cacertdir: specdirectory]')
          }
          it {
            is_expected.to contain_exec('Add trust for server cert: specdirectory').with(
              command: 'certutil -M -n "Spec Certificate" -t u,u,u -d /etc/dirsrv/slapd-specdirectory',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              unless: 'certutil -L -d /etc/dirsrv/slapd-specdirectory | grep "Spec Certificate" | grep "u,u,u"',
            ).that_notifies('Exec[Export server cert: specdirectory]')
          }

          it { is_expected.not_to contain_exec('Generate noise file: specdirectory') }
        end

        context 'when setting up replication' do
          let(:params) do
            {
              root_dn: 'cn=Directory Manager',
              suffix: 'dc=example,dc=com',
              cert_db_pass: 'secret',
              root_dn_pass: 'supersecure',
              server_id: 'specdirectory',
              replication: {
                'replication_pass' => 'supersecret',
                'role' => 'consumer',
              },
            }
          end

          it { is_expected.to compile }

          it {
            is_expected.to contain_ds_389__replication('specdirectory').with(
              replication_pass: 'supersecret',
              role: 'consumer',
              root_dn: 'cn=Directory Manager',
              root_dn_pass: 'supersecure',
              suffix: 'dc=example,dc=com',
              server_host: 'foo.example.com',
              server_port: 389,
              starttls: false,
              user: 'dirsrv',
              group: 'dirsrv',
            ).that_requires('Ds_389::Ssl[specdirectory]')
          }
        end

        context 'when loading additional ldifs' do
          let(:params) do
            {
              root_dn: 'cn=Directory Manager',
              suffix: 'dc=example,dc=com',
              cert_db_pass: 'secret',
              root_dn_pass: 'supersecure',
              server_id: 'specdirectory',
              modify_ldifs: {
                'specmodify1' => 'puppet:///specfiles/specmodify1.ldif',
                'specmodify2' => 'puppet:///specfiles/specmodify2.ldif',
              },
              add_ldifs: {
                'specadd1' => 'puppet:///specfiles/specadd1.ldif',
                'specadd2' => 'puppet:///specfiles/specadd2.ldif',
              },
              base_load_ldifs: {
                'specbaseload1' => 'puppet:///specfiles/specbaseload1.ldif',
                'specbaseload2' => 'puppet:///specfiles/specbaseload2.ldif',
              },
            }
          end

          it { is_expected.to compile }

          it {
            is_expected.to contain_ds_389__modify('specmodify1').with(
              server_id: 'specdirectory',
              root_dn: 'cn=Directory Manager',
              root_dn_pass: 'supersecure',
              server_host: 'foo.example.com',
              server_port: 389,
              starttls: false,
              source: 'puppet:///specfiles/specmodify1.ldif',
              user: 'dirsrv',
              group: 'dirsrv',
            ).that_requires('Ds_389::Ssl[specdirectory]')
          }
          it { is_expected.to contain_file('/etc/dirsrv/slapd-specdirectory/specmodify1.ldif') }
          it { is_expected.to contain_exec('Modify ldif specmodify1: specdirectory') }
          it {
            is_expected.to contain_ds_389__modify('specmodify2').with(
              server_id: 'specdirectory',
              root_dn: 'cn=Directory Manager',
              root_dn_pass: 'supersecure',
              server_host: 'foo.example.com',
              server_port: 389,
              starttls: false,
              source: 'puppet:///specfiles/specmodify2.ldif',
              user: 'dirsrv',
              group: 'dirsrv',
            ).that_requires('Ds_389::Ssl[specdirectory]')
          }
          it { is_expected.to contain_file('/etc/dirsrv/slapd-specdirectory/specmodify2.ldif') }
          it { is_expected.to contain_exec('Modify ldif specmodify2: specdirectory') }

          it {
            is_expected.to contain_ds_389__add('specadd1').with(
              server_id: 'specdirectory',
              root_dn: 'cn=Directory Manager',
              root_dn_pass: 'supersecure',
              server_host: 'foo.example.com',
              server_port: 389,
              starttls: false,
              source: 'puppet:///specfiles/specadd1.ldif',
              user: 'dirsrv',
              group: 'dirsrv',
            )
          }
          it { is_expected.to contain_file('/etc/dirsrv/slapd-specdirectory/specadd1.ldif') }
          it { is_expected.to contain_exec('Add ldif specadd1: specdirectory') }
          it {
            is_expected.to contain_ds_389__add('specadd2').with(
              server_id: 'specdirectory',
              root_dn: 'cn=Directory Manager',
              root_dn_pass: 'supersecure',
              server_host: 'foo.example.com',
              server_port: 389,
              starttls: false,
              source: 'puppet:///specfiles/specadd2.ldif',
              user: 'dirsrv',
              group: 'dirsrv',
            )
          }
          it { is_expected.to contain_file('/etc/dirsrv/slapd-specdirectory/specadd2.ldif') }
          it { is_expected.to contain_exec('Add ldif specadd2: specdirectory') }

          it {
            is_expected.to contain_ds_389__add('specbaseload1').with(
              server_id: 'specdirectory',
              root_dn: 'cn=Directory Manager',
              root_dn_pass: 'supersecure',
              server_host: 'foo.example.com',
              server_port: 389,
              starttls: false,
              source: 'puppet:///specfiles/specbaseload1.ldif',
              user: 'dirsrv',
              group: 'dirsrv',
            )
          }
          it { is_expected.to contain_file('/etc/dirsrv/slapd-specdirectory/specbaseload1.ldif') }
          it { is_expected.to contain_exec('Add ldif specbaseload1: specdirectory') }
          it {
            is_expected.to contain_ds_389__add('specbaseload2').with(
              server_id: 'specdirectory',
              root_dn: 'cn=Directory Manager',
              root_dn_pass: 'supersecure',
              server_host: 'foo.example.com',
              server_port: 389,
              starttls: false,
              source: 'puppet:///specfiles/specbaseload2.ldif',
              user: 'dirsrv',
              group: 'dirsrv',
            )
          }
          it { is_expected.to contain_file('/etc/dirsrv/slapd-specdirectory/specbaseload2.ldif') }
          it { is_expected.to contain_exec('Add ldif specbaseload2: specdirectory') }
        end

        context 'when using custom ds_389 params' do
          let(:pre_condition) do
            'class {"::ds_389":
               user         => "custom_user",
               group        => "custom_group",
               cacerts_path => "/custom/cacerts/path",
            }'
          end
          let(:params) do
            {
              root_dn: 'cn=Directory Manager',
              suffix: 'dc=example,dc=com',
              cert_db_pass: 'secret',
              root_dn_pass: 'supersecure',
              server_id: 'specdirectory',
            }
          end

          it { is_expected.to compile }

          it {
            is_expected.to contain_file('/etc/dirsrv/slapd-specdirectory/pin.txt').with(
              ensure: 'file',
              mode: '0440',
              owner: 'custom_user',
              group: 'custom_group',
              content: "Internal (Software) Token:supersecure\n",
            ).that_requires('Exec[setup ds: specdirectory]').that_notifies(
              'Exec[restart specdirectory to pick up new token]',
            )
          }

          it {
            is_expected.to contain_exec('Set permissions on database directory: specdirectory').with(
              command: 'chown custom_user:custom_group /etc/dirsrv/slapd-specdirectory',
              refreshonly: true,
            )
          }

          it {
            is_expected.to contain_file('/custom/cacerts/path/specdirectoryCA.pem').with(
              ensure: 'file',
              source: '/etc/dirsrv/slapd-specdirectory/specdirectoryCA.pem',
            ).that_requires('Exec[Export CA cert: specdirectory]').that_notifies(
              'Exec[Rehash cacertdir: specdirectory]',
            )
          }

          it {
            is_expected.to contain_file('/custom/cacerts/path/specdirectoryCert.pem').with(
              ensure: 'file',
              source: '/etc/dirsrv/slapd-specdirectory/specdirectoryCert.pem',
            ).that_requires('Exec[Export server cert: specdirectory]').that_notifies(
              'Exec[Rehash cacertdir: specdirectory]',
            )
          }

          it {
            is_expected.to contain_exec('setup ds: specdirectory').with(
              command: 'dscreate from-file /etc/dirsrv/template-specdirectory.inf',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              creates: '/etc/dirsrv/slapd-specdirectory',
            )
          }

          it {
            is_expected.to contain_exec('Rehash cacertdir: specdirectory').with(
              command: 'openssl rehash /custom/cacerts/path',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              refreshonly: true,
            )
          }

          it {
            is_expected.to contain_ds_389__ssl('specdirectory').with(
              cert_name: 'specdirectoryCert',
              root_dn: 'cn=Directory Manager',
              root_dn_pass: 'supersecure',
              server_host: 'foo.example.com',
              server_port: 389,
              user: 'custom_user',
              group: 'custom_group',
              minssf: 0,
              ssl_version_min: 'TLS1.1',
            )
          }
        end
      end

      context 'with all params' do
        let(:params) do
          {
            root_dn: 'cn=Directory Manager',
            suffix: 'dc=test,dc=org',
            cert_db_pass: 'secret',
            root_dn_pass: 'supersecure',
            group: 'custom_group',
            user: 'custom_user',
            server_id: 'ldap01',
            server_host: 'ldap.test.org',
            server_port: 1389,
            server_ssl_port: 1636,
            minssf: 128,
            subject_alt_names: ['ldap01.test.org', 'ldap02.test.org'],
          }
        end

        it { is_expected.to compile }

        it {
          is_expected.to contain_file('/etc/dirsrv/slapd-ldap01/pin.txt').with(
            ensure: 'file',
            mode: '0440',
            owner: 'custom_user',
            group: 'custom_group',
            content: "Internal (Software) Token:supersecure\n",
          ).that_requires('Exec[setup ds: ldap01]').that_notifies(
            'Exec[restart ldap01 to pick up new token]',
          )
        }

        case os_facts[:kernel]
        when 'Linux'
          it {
            is_expected.to contain_exec('setup ds: ldap01').with(
              command: 'dscreate from-file /etc/dirsrv/template-ldap01.inf',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              creates: '/etc/dirsrv/slapd-ldap01',
            )
          }

          it {
            is_expected.to contain_exec('Rehash cacertdir: ldap01').with(
              command: 'openssl rehash /etc/openldap/cacerts',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              refreshonly: true,
            )
          }

          it {
            is_expected.to contain_exec('stop ldap01 to create new token').with(
              command: 'systemctl stop dirsrv@ldap01 ; sleep 2',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              refreshonly: true,
            )
          }

          it {
            is_expected.to contain_exec('restart ldap01 to pick up new token').with(
              command: 'systemctl restart dirsrv@ldap01 ; sleep 2',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              refreshonly: true,
            )
          }
        else
          it {
            is_expected.to contain_exec('stop ldap01 to create new token').with(
              command: 'service dirsrv stop ldap01 ; sleep 2',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              refreshonly: true,
            )
          }

          it {
            is_expected.to contain_exec('restart ldap01 to pick up new token').with(
              command: 'service dirsrv restart ldap01 ; sleep 2',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              refreshonly: true,
            )
          }
        end

        it {
          is_expected.to contain_exec('Generate password file: ldap01').with(
            command: 'echo supersecure > /tmp/passfile-ldap01',
            path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            refreshonly: true,
          ).that_subscribes_to('Exec[Create cert DB: ldap01]')
        }

        it {
          is_expected.to contain_exec('Create cert DB: ldap01').with(
            command: 'certutil -N -d /etc/dirsrv/slapd-ldap01 -f /tmp/passfile-ldap01',
            path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            refreshonly: true,
          ).that_notifies('Ssl_pkey[Generate CA private key: ldap01]')
        }

        it {
          is_expected.to contain_ssl_pkey('Generate CA private key: ldap01').with(
            size: 4096,
          )
        }

        it {
          is_expected.to contain_x509_cert('Create CA cert: ldap01').with(
            days: 3650,
            req_ext: false,
          )
        }

        it {
          is_expected.to contain_exec('Add trust for CA: ldap01').with(
            command: 'certutil -M -n "ldap01CA" -t CT,C,C -d /etc/dirsrv/slapd-ldap01 -f /tmp/passfile-ldap01',
            path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            unless: 'certutil -L -d /etc/dirsrv/slapd-ldap01 | grep "ldap01CA" | grep "CTu,Cu,Cu"',
          ).that_notifies(
            [
              'Exec[Export CA cert: ldap01]',
              'Exec[Clean up temp passwd file: ldap01]',
            ],
          )
        }

        it {
          is_expected.to contain_exec('Make server cert and add to database: ldap01').with(
            cwd: '/etc/dirsrv/slapd-ldap01',
            command: 'certutil -S -n "ldap01Cert" -m 101 -s "cn=ldap.test.org" -c "ldap01CA" -t "u,u,u" -v 120 -d /etc/dirsrv/slapd-ldap01 -k rsa -z /tmp/noisefile-ldap01 -f /tmp/passfile-ldap01 -8 ldap01.test.org,ldap02.test.org && sleep 2', # rubocop:disable LineLength
            path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            refreshonly: true,
          ).that_notifies(
            [
              'Exec[Set permissions on database directory: ldap01]',
              'Exec[Clean up temp passwd file: ldap01]',
              'Exec[Clean up temp noise file: ldap01]',
              'Exec[Add trust for server cert: ldap01]',
            ],
          )
        }

        it {
          is_expected.to contain_exec('Add trust for server cert: ldap01').with(
            command: 'certutil -M -n "ldap01Cert" -t u,u,u -d /etc/dirsrv/slapd-ldap01',
            path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            unless: 'certutil -L -d /etc/dirsrv/slapd-ldap01 | grep "ldap01Cert" | grep "u,u,u"',
          ).that_notifies('Exec[Export server cert: ldap01]')
        }

        it {
          is_expected.to contain_exec('Set permissions on database directory: ldap01').with(
            command: 'chown custom_user:custom_group /etc/dirsrv/slapd-ldap01',
            refreshonly: true,
          )
        }

        it {
          is_expected.to contain_exec('Export CA cert: ldap01').with(
            cwd: '/etc/dirsrv/slapd-ldap01',
            command: 'certutil -d /etc/dirsrv/slapd-ldap01 -L -n "ldap01CA" -a > /etc/dirsrv/slapd-ldap01/ldap01CA.pem',
            path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            creates: '/etc/dirsrv/slapd-ldap01/ldap01CA.pem',
          )
        }

        it {
          is_expected.to contain_file('/etc/openldap/cacerts/ldap01CA.pem').with(
            ensure: 'file',
            source: '/etc/dirsrv/slapd-ldap01/ldap01CA.pem',
          ).that_requires('Exec[Export CA cert: ldap01]').that_notifies(
            'Exec[Rehash cacertdir: ldap01]',
          )
        }

        it {
          is_expected.to contain_exec('Clean up temp passwd file: ldap01').with(
            command: 'rm -f /tmp/passfile-ldap01',
            refreshonly: true,
          )
        }

        it {
          is_expected.to contain_exec('Clean up temp noise file: ldap01').with(
            command: 'rm -f /tmp/noisefile-ldap01',
            refreshonly: true,
          )
        }

        it {
          is_expected.to contain_exec('Export server cert: ldap01').with(
            cwd: '/etc/dirsrv/slapd-ldap01',
            command: 'certutil -d /etc/dirsrv/slapd-ldap01 -L -n "ldap01Cert" -a > ldap01Cert.pem',
            path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            creates: '/etc/dirsrv/slapd-ldap01/ldap01Cert.pem',
          )
        }

        it {
          is_expected.to contain_file('/etc/openldap/cacerts/ldap01Cert.pem').with(
            ensure: 'file',
            source: '/etc/dirsrv/slapd-ldap01/ldap01Cert.pem',
          ).that_requires('Exec[Export server cert: ldap01]').that_notifies(
            'Exec[Rehash cacertdir: ldap01]',
          )
        }

        it {
          is_expected.to contain_ds_389__ssl('ldap01').with(
            cert_name: 'ldap01Cert',
            root_dn: 'cn=Directory Manager',
            root_dn_pass: 'supersecure',
            server_host: 'ldap.test.org',
            server_port: 1389,
            user: 'custom_user',
            group: 'custom_group',
            minssf: 128,
            ssl_version_min: 'TLS1.1',
          )
        }

        it { is_expected.to contain_ds_389__service('ldap01') }

        it { is_expected.to contain_exec('Import ssl ldif: ldap01') }
        it { is_expected.to contain_file('/etc/dirsrv/slapd-ldap01/ssl.ldif') }
        it { is_expected.to contain_service('dirsrv@ldap01') }

        it { is_expected.not_to contain_concat__fragment('ldap01_cert') }
        it { is_expected.not_to contain_concat__fragment('ldap01_ca_bundle') }
        it { is_expected.not_to contain_concat__fragment('ldap01_key') }
        it { is_expected.not_to contain_concat('ldap01_cert_bundle') }
        it { is_expected.not_to contain_exec('Create pkcs12 cert: ldap01') }
        it { is_expected.not_to contain_exec('Add trust for CA0: ldap01') }
        it { is_expected.not_to contain_exec('Export CA cert 0: ldap01') }
        it { is_expected.not_to contain_file('/etc/openldap/cacerts/ldap01CA0.pem') }

        context 'when importing an external ssl cert bundle' do
          let(:params) do
            {
              root_dn: 'cn=Directory Manager',
              suffix: 'dc=test,dc=org',
              cert_db_pass: 'secret',
              root_dn_pass: 'supersecure',
              group: 'custom_group',
              user: 'custom_user',
              server_id: 'ldap01',
              server_host: 'ldap.test.org',
              server_port: 1389,
              server_ssl_port: 1636,
              subject_alt_names: ['ldap01.test.org', 'ldap02.test.org'],
              ssl: {
                'cert_path' => 'puppet:///specfiles/ssl_cert.pem',
                'key_path' => 'puppet:///specfiles/ssl_key.pem',
                'ca_bundle_path' => 'puppet:///specfiles/ssl_ca.pem',
                'ca_cert_names' => [
                  'Spec Intermediate Certificate',
                  'Spec Root Certificate',
                ],
                'cert_name' => 'Spec Certificate',
              },
            }
          end

          it { is_expected.to compile }

          it {
            is_expected.to contain_concat__fragment('ldap01_cert').with(
              target: 'ldap01_cert_bundle',
              source: 'puppet:///specfiles/ssl_cert.pem',
              order: '0',
            )
          }
          it {
            is_expected.to contain_concat__fragment('ldap01_ca_bundle').with(
              target: 'ldap01_cert_bundle',
              source: 'puppet:///specfiles/ssl_ca.pem',
              order: '1',
            )
          }
          it {
            is_expected.to contain_concat__fragment('ldap01_key').with(
              target: 'ldap01_cert_bundle',
              source: 'puppet:///specfiles/ssl_key.pem',
              order: '2',
            )
          }

          case os_facts[:osfamily]
          when 'Debian'
            it {
              is_expected.to contain_concat('ldap01_cert_bundle').with(
                mode: '0600',
                path: '/etc/ssl/ldap01-bundle.pem',
              ).that_notifies('Exec[Create pkcs12 cert: ldap01]')
            }
            it {
              is_expected.to contain_exec('Create pkcs12 cert: ldap01').with(
                command: 'openssl pkcs12 -export -password pass:secret -name ldap.test.org -in /etc/ssl/ldap01-bundle.pem -out /etc/ssl/ldap01.p12',
                path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
                refreshonly: true,
              ).that_notifies('Exec[Create cert DB: ldap01]')
            }
            it {
              is_expected.to contain_exec('Create cert DB: ldap01').with(
                command: 'pk12util -i /etc/ssl/ldap01.p12 -d /etc/dirsrv/slapd-ldap01 -W secret -K supersecure',
                path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
                refreshonly: true,
              )
            }
          when 'RedHat'
            it {
              is_expected.to contain_concat('ldap01_cert_bundle').with(
                mode: '0600',
                path: '/etc/pki/tls/certs/ldap01-bundle.pem',
              ).that_notifies('Exec[Create pkcs12 cert: ldap01]')
            }
            it {
              is_expected.to contain_exec('Create pkcs12 cert: ldap01').with(
                command: 'openssl pkcs12 -export -password pass:secret -name ldap.test.org -in /etc/pki/tls/certs/ldap01-bundle.pem -out /etc/pki/tls/certs/ldap01.p12',
                path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
                refreshonly: true,
              ).that_notifies('Exec[Create cert DB: ldap01]')
            }
            it {
              is_expected.to contain_exec('Create cert DB: ldap01').with(
                command: 'pk12util -i /etc/pki/tls/certs/ldap01.p12 -d /etc/dirsrv/slapd-ldap01 -W secret -K supersecure',
                path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
                refreshonly: true,
              ).that_notifies('Exec[Generate password file: ldap01]')
            }
          end

          it {
            is_expected.to contain_exec('Generate password file: ldap01').with(
              command: 'echo supersecure > /tmp/passfile-ldap01',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              refreshonly: true,
            )
          }

          it {
            is_expected.to contain_exec('Add trust for CA0: ldap01').with(
              command: 'certutil -M -n "Spec Intermediate Certificate" -t CT,, -d /etc/dirsrv/slapd-ldap01 -f /tmp/passfile-ldap01',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              unless: 'certutil -L -d /etc/dirsrv/slapd-ldap01 | grep "Spec Intermediate Certificate" | grep "CT"',
            ).that_requires(
              [
                'Exec[Create cert DB: ldap01]',
                'Exec[Generate password file: ldap01]',
              ],
            ).that_notifies(
              [
                'Exec[Export CA cert 0: ldap01]',
                'Exec[Clean up temp passwd file: ldap01]',
              ],
            )
          }
          it {
            is_expected.to contain_exec('Export CA cert 0: ldap01').with(
              cwd: '/etc/dirsrv/slapd-ldap01',
              command: 'certutil -d /etc/dirsrv/slapd-ldap01 -L -n "Spec Intermediate Certificate" -a > ldap01CA0.pem',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              creates: '/etc/dirsrv/slapd-ldap01/ldap01CA0.pem',
            )
          }
          it {
            is_expected.to contain_file('/etc/openldap/cacerts/ldap01CA0.pem').with(
              ensure: 'file',
              source: '/etc/dirsrv/slapd-ldap01/ldap01CA0.pem',
            ).that_requires('Exec[Export CA cert 0: ldap01]').that_notifies('Exec[Rehash cacertdir: ldap01]')
          }

          it {
            is_expected.to contain_exec('Add trust for CA1: ldap01').with(
              command: 'certutil -M -n "Spec Root Certificate" -t CT,, -d /etc/dirsrv/slapd-ldap01 -f /tmp/passfile-ldap01',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              unless: 'certutil -L -d /etc/dirsrv/slapd-ldap01 | grep "Spec Root Certificate" | grep "CT"',
            ).that_requires(
              [
                'Exec[Create cert DB: ldap01]',
                'Exec[Generate password file: ldap01]',
              ],
            ).that_notifies(
              [
                'Exec[Export CA cert 1: ldap01]',
                'Exec[Clean up temp passwd file: ldap01]',
              ],
            )
          }
          it {
            is_expected.to contain_exec('Export CA cert 1: ldap01').with(
              cwd: '/etc/dirsrv/slapd-ldap01',
              command: 'certutil -d /etc/dirsrv/slapd-ldap01 -L -n "Spec Root Certificate" -a > ldap01CA1.pem',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              creates: '/etc/dirsrv/slapd-ldap01/ldap01CA1.pem',
            )
          }
          it {
            is_expected.to contain_file('/etc/openldap/cacerts/ldap01CA1.pem').with(
              ensure: 'file',
              source: '/etc/dirsrv/slapd-ldap01/ldap01CA1.pem',
            ).that_requires('Exec[Export CA cert 1: ldap01]').that_notifies('Exec[Rehash cacertdir: ldap01]')
          }
          it {
            is_expected.to contain_exec('Add trust for server cert: ldap01').with(
              command: 'certutil -M -n "Spec Certificate" -t u,u,u -d /etc/dirsrv/slapd-ldap01',
              path: '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
              unless: 'certutil -L -d /etc/dirsrv/slapd-ldap01 | grep "Spec Certificate" | grep "u,u,u"',
            ).that_notifies('Exec[Export server cert: ldap01]')
          }

          it { is_expected.not_to contain_exec('Generate noise file: ldap01') }
        end

        context 'when setting up replication' do
          let(:params) do
            {
              root_dn: 'cn=Directory Manager',
              suffix: 'dc=test,dc=org',
              cert_db_pass: 'secret',
              root_dn_pass: 'supersecure',
              group: 'custom_group',
              user: 'custom_user',
              server_id: 'ldap01',
              server_host: 'ldap.test.org',
              server_port: 1389,
              server_ssl_port: 1636,
              subject_alt_names: ['ldap01.test.org', 'ldap02.test.org'],
              minssf: 128,
              replication: {
                'bind_dn' => 'cn=Replication Manager,cn=config',
                'replication_pass' => 'supersecret',
                'role' => 'consumer',
              },
            }
          end

          it { is_expected.to compile }

          it {
            is_expected.to contain_ds_389__replication('ldap01').with(
              replication_pass: 'supersecret',
              role: 'consumer',
              root_dn: 'cn=Directory Manager',
              root_dn_pass: 'supersecure',
              suffix: 'dc=test,dc=org',
              server_host: 'ldap.test.org',
              server_port: 1389,
              starttls: true,
              user: 'custom_user',
              group: 'custom_group',
            ).that_requires('Ds_389::Ssl[ldap01]')
          }

          it { is_expected.to contain_exec('Add replication user: ldap01') }
          it { is_expected.to contain_file('/etc/dirsrv/slapd-ldap01/replication-user.ldif') }
        end

        context 'when loading additional ldifs' do
          let(:params) do
            {
              root_dn: 'cn=Directory Manager',
              suffix: 'dc=test,dc=org',
              cert_db_pass: 'secret',
              root_dn_pass: 'supersecure',
              group: 'custom_group',
              user: 'custom_user',
              server_id: 'ldap01',
              server_host: 'ldap.test.org',
              server_port: 1389,
              server_ssl_port: 1636,
              subject_alt_names: ['ldap01.test.org', 'ldap02.test.org'],
              minssf: 128,
              modify_ldifs: {
                'specmodify1' => 'puppet:///specfiles/specmodify1.ldif',
                'specmodify2' => 'puppet:///specfiles/specmodify2.ldif',
              },
              add_ldifs: {
                'specadd1' => 'puppet:///specfiles/specadd1.ldif',
                'specadd2' => 'puppet:///specfiles/specadd2.ldif',
              },
              base_load_ldifs: {
                'specbaseload1' => 'puppet:///specfiles/specbaseload1.ldif',
                'specbaseload2' => 'puppet:///specfiles/specbaseload2.ldif',
              },
            }
          end

          it { is_expected.to compile }

          it {
            is_expected.to contain_ds_389__modify('specmodify1').with(
              server_id: 'ldap01',
              root_dn: 'cn=Directory Manager',
              root_dn_pass: 'supersecure',
              server_host: 'ldap.test.org',
              server_port: 1389,
              starttls: true,
              source: 'puppet:///specfiles/specmodify1.ldif',
              user: 'custom_user',
              group: 'custom_group',
            )
          }
          it { is_expected.to contain_file('/etc/dirsrv/slapd-ldap01/specmodify1.ldif') }
          it { is_expected.to contain_exec('Modify ldif specmodify1: ldap01') }
          it {
            is_expected.to contain_ds_389__modify('specmodify2').with(
              server_id: 'ldap01',
              root_dn: 'cn=Directory Manager',
              root_dn_pass: 'supersecure',
              server_host: 'ldap.test.org',
              server_port: 1389,
              starttls: true,
              source: 'puppet:///specfiles/specmodify2.ldif',
              user: 'custom_user',
              group: 'custom_group',
            )
          }
          it { is_expected.to contain_file('/etc/dirsrv/slapd-ldap01/specmodify2.ldif') }
          it { is_expected.to contain_exec('Modify ldif specmodify2: ldap01') }

          it {
            is_expected.to contain_ds_389__add('specadd1').with(
              server_id: 'ldap01',
              root_dn: 'cn=Directory Manager',
              root_dn_pass: 'supersecure',
              server_host: 'ldap.test.org',
              server_port: 1389,
              starttls: true,
              source: 'puppet:///specfiles/specadd1.ldif',
              user: 'custom_user',
              group: 'custom_group',
            )
          }
          it { is_expected.to contain_file('/etc/dirsrv/slapd-ldap01/specadd1.ldif') }
          it { is_expected.to contain_exec('Add ldif specadd1: ldap01') }
          it {
            is_expected.to contain_ds_389__add('specadd2').with(
              server_id: 'ldap01',
              root_dn: 'cn=Directory Manager',
              root_dn_pass: 'supersecure',
              server_host: 'ldap.test.org',
              server_port: 1389,
              starttls: true,
              source: 'puppet:///specfiles/specadd2.ldif',
              user: 'custom_user',
              group: 'custom_group',
            )
          }
          it { is_expected.to contain_file('/etc/dirsrv/slapd-ldap01/specadd2.ldif') }
          it { is_expected.to contain_exec('Add ldif specadd2: ldap01') }

          it {
            is_expected.to contain_ds_389__add('specbaseload1').with(
              server_id: 'ldap01',
              root_dn: 'cn=Directory Manager',
              root_dn_pass: 'supersecure',
              server_host: 'ldap.test.org',
              server_port: 1389,
              starttls: true,
              source: 'puppet:///specfiles/specbaseload1.ldif',
              user: 'custom_user',
              group: 'custom_group',
            )
          }
          it { is_expected.to contain_file('/etc/dirsrv/slapd-ldap01/specbaseload1.ldif') }
          it { is_expected.to contain_exec('Add ldif specbaseload1: ldap01') }
          it {
            is_expected.to contain_ds_389__add('specbaseload2').with(
              server_id: 'ldap01',
              root_dn: 'cn=Directory Manager',
              root_dn_pass: 'supersecure',
              server_host: 'ldap.test.org',
              server_port: 1389,
              starttls: true,
              source: 'puppet:///specfiles/specbaseload2.ldif',
              user: 'custom_user',
              group: 'custom_group',
            )
          }
          it { is_expected.to contain_file('/etc/dirsrv/slapd-ldap01/specbaseload2.ldif') }
          it { is_expected.to contain_exec('Add ldif specbaseload2: ldap01') }
        end
      end
    end
  end
end
