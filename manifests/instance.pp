# @summary Manages a 389 ds instance.
#
# @example A basic instance with required params.
#   ds_389::instance { 'foo':
#     root_dn      => 'cn=Directory Manager',
#     suffix       => 'dc=example,dc=com',
#     cert_db_pass => 'secret',
#     root_dn_pass => 'supersecure',
#     server_id    => 'specdirectory',
#   }
#
# @param add_ldifs
#   A hash of ldif add files. See add.pp. Optional.
#
# @param backup_enable
#   Whether to enable a periodic backup job for this instance.
#
# @param backup_notls
#   Whether to disable TLS connection for the backup job.
#
# @param base_load_ldifs
#   A hash of ldif add files to load after all other config files have been added. Optional.
#
# @param cert_db_pass
#   The certificate db password to ensure. Required.
#
# @param create_suffix
#   Set this parameter to `True` to create a generic root node entry for the suffix in the database.
#
# @param group
#   The group for the instance. Default: `$ds_389::group`
#
# @param minssf
#   The minimum security strength for connections. Default: 0
#
# @param modify_ldifs
#   A hash of ldif modify files. See modify.pp. Optional.
#
# @param plugins
#   A hash of plugins to enable or disable. See plugin.pp. Optional.
#
# @param replication
#   A replication config hash. See replication.pp. Optional.
#
# @param root_dn_pass
#   The root dn password to ensure. Required.
#
# @param root_dn
#   The root dn to ensure. Required.
#
# @param schema_extensions
#   A hash of schemas to ensure. See schema.pp. Optional.
#
# @param server_host
#   The fqdn for the instance. Default: `$facts['networking']['fqdn']`
#
# @param server_id
#   The server identifier for the instance. Default: `$facts['networking']['hostname']`
#
# @param server_port
#   The port to use for non-SSL traffic. Default: 389
#
# @param server_ssl_port
#   The port to use for SSL traffic. Default: 636
#
# @param ssl
#   An ssl config hash. See ssl.pp. Optional.
#
# @param ssl_version_min
#   The minimum TLS version the instance should support. Optional.
#
# @param subject_alt_names
#   An array of subject alt names, if using self-signed certificates. Optional.
#
# @param suffix
#   The LDAP suffix to use. Required.
#
# @param user
#   The user for the instance. Default: $ds_389::user
#
define ds_389::instance (
  Variant[String,Sensitive[String]] $cert_db_pass,
  String $root_dn,
  Variant[String,Sensitive[String]] $root_dn_pass,
  String $suffix,
  Boolean $backup_enable = false,
  Boolean $backup_notls = false,
  Boolean $create_suffix = true,
  String $group = $ds_389::group,
  Integer $minssf = 0,
  String $server_host = $facts['networking']['fqdn'],
  String $server_id = $facts['networking']['hostname'],
  Integer $server_port = 389,
  Integer $server_ssl_port = 636,
  String $user = $ds_389::user,
  Optional[Hash] $add_ldifs = undef,
  Optional[Hash] $base_load_ldifs = undef,
  Optional[Hash] $modify_ldifs = undef,
  Optional[Hash] $plugins = undef,
  Optional[Hash] $replication = undef,
  Optional[Hash] $schema_extensions = undef,
  Optional[Hash] $ssl = undef,
  Optional[String] $ssl_version_min = undef,
  Optional[Array] $subject_alt_names = undef,
) {
  include ds_389

  $instance_path = "/etc/dirsrv/slapd-${server_id}"
  $instance_template = "/etc/dirsrv/template-${server_id}.inf"

  # Create instance template.
  file { $instance_template:
    ensure  => file,
    mode    => '0400',
    owner   => $user,
    group   => $group,
    content => epp("${module_name}/instance.epp",{
      create_suffix   => $create_suffix,
      group           => $group,
      root_dn         => $root_dn,
      root_dn_pass    => $root_dn_pass,
      server_host     => $server_host,
      server_id       => $server_id,
      server_port     => $server_port,
      server_ssl_port => $server_ssl_port,
      suffix          => $suffix,
      user            => $user,
    }),
  }

  # Create a new instance from template file.
  exec { "setup ds: ${server_id}":
    command => "dscreate from-file ${instance_template}",
    path    => $ds_389::path,
    creates => $instance_path,
    require => File[$instance_template],
    notify  => Exec["stop ${server_id} to create new token"],
  }
  ~> exec { "remove default cert DB: ${server_id}":
    command     => "rm -f ${$instance_path}/cert9.db ${$instance_path}/key4.db",
    path        => $ds_389::path,
    refreshonly => true,
  }

  if $ds_389::service_type == 'systemd' {
    $service_stop_command = "systemctl stop dirsrv@${server_id}"
    $service_restart_command = "systemctl restart dirsrv@${server_id}"
  }
  else {
    $service_stop_command = "service dirsrv stop ${server_id}"
    $service_restart_command = "service dirsrv restart ${server_id}"
  }

  exec { "stop ${server_id} to create new token":
    command     => "${service_stop_command} ; sleep 2",
    refreshonly => true,
    path        => $ds_389::path,
    before      => File["${instance_path}/pin.txt"],
  }

  file { "${instance_path}/pin.txt":
    ensure    => file,
    mode      => '0440',
    owner     => $user,
    group     => $group,
    content   => "Internal (Software) Token:${root_dn_pass}\n",
    show_diff => false,
    require   => Exec["setup ds: ${server_id}"],
    notify    => Exec["restart ${server_id} to pick up new token"],
  }

  # If we have existing certs, create cert db and import certs.
  if $ssl {
    # concat bundle
    concat::fragment { "${server_id}_cert":
      target => "${server_id}_cert_bundle",
      source => $ssl['cert_path'],
      order  => '0',
    }
    concat::fragment { "${server_id}_ca_bundle":
      target => "${server_id}_cert_bundle",
      source => $ssl['ca_bundle_path'],
      order  => '1',
    }
    concat::fragment { "${server_id}_key":
      target => "${server_id}_cert_bundle",
      source => $ssl['key_path'],
      order  => '2',
    }
    concat { "${server_id}_cert_bundle":
      mode           => '0600',
      path           => "${ds_389::ssl_dir}/${server_id}-bundle.pem",
      ensure_newline => true,
      notify         => Exec["Create pkcs12 cert: ${server_id}"],
    }

    exec { "Create pkcs12 cert: ${server_id}":
      command     => "openssl pkcs12 -export -password pass:${cert_db_pass} -name ${server_host} -in ${ds_389::ssl_dir}/${server_id}-bundle.pem -out ${ds_389::ssl_dir}/${server_id}.p12", # lint:ignore:140chars
      path        => $ds_389::path,
      refreshonly => true,
      notify      => Exec["Create cert DB: ${server_id}"],
    }

    exec { "Create cert DB: ${server_id}":
      command     => "pk12util -i ${ds_389::ssl_dir}/${server_id}.p12 -d ${instance_path} -W ${cert_db_pass} -K ${root_dn_pass}", # lint:ignore:140chars
      path        => $ds_389::path,
      refreshonly => true,
      before      => Exec["Add trust for server cert: ${server_id}"],
    }

    $ssl['ca_cert_names'].each |$index, $cert_name| {
      exec { "Add trust for CA${index}: ${server_id}":
        command => "certutil -M -n \"${cert_name}\" -t CT,, -d ${instance_path}",
        path    => $ds_389::path,
        unless  => "certutil -L -d ${instance_path} | grep \"${cert_name}\" | grep \"CT\"",
        require => Exec["Create cert DB: ${server_id}"],
        notify  => Exec["Export CA cert ${index}: ${server_id}"],
      }
      # - export ca cert
      exec { "Export CA cert ${index}: ${server_id}":
        cwd     => $instance_path,
        command => "certutil -d ${instance_path} -L -n \"${cert_name}\" -a > ${server_id}CA${index}.pem",
        path    => $ds_389::path,
        creates => "${instance_path}/${server_id}CA${index}.pem",
      }
      # - copy ca certs to openldap
      file { "${ds_389::cacerts_path}/${server_id}CA${index}.pem":
        ensure  => file,
        source  => "${instance_path}/${server_id}CA${index}.pem",
        require => Exec["Export CA cert ${index}: ${server_id}"],
        notify  => Exec["Rehash cacertdir: ${server_id}"],
      }
    }

    $ssl_cert_name = $ssl['cert_name']
    exec { "Add trust for server cert: ${server_id}":
      command => "certutil -M -n \"${ssl['cert_name']}\" -t u,u,u -d ${instance_path}",
      path    => $ds_389::path,
      unless  => "certutil -L -d ${instance_path} | grep \"${ssl['cert_name']}\" | grep \"u,u,u\"",
      notify  => Exec["Export server cert: ${server_id}"],
    }
  }

  # Otherwise gen certs and add to db.
  else {
    if $subject_alt_names {
      $san_string = join($subject_alt_names, ',')
      $sans = "-8 ${san_string}"
    }
    else {
      $sans = undef
    }

    # Certificate attributes and filenames.
    $ca_key = "${instance_path}/${server_id}CA-Key.pem"
    $ca_conf = "${instance_path}/${server_id}CA.cnf"
    $ca_cert = "${instance_path}/${server_id}CA.pem"
    $ca_p12 = "${instance_path}/${server_id}CA.p12"
    $ca_nickname = "${server_id}CA"
    $ssl_cert_name = "${server_id}Cert"

    # Create noise file.
    $temp_noise_file = "/tmp/noisefile-${server_id}"
    $temp_pass_file = "/tmp/passfile-${server_id}"
    $rand_int = fqdn_rand(32)
    exec { "Generate noise file: ${server_id}":
      command     => "echo ${rand_int} | sha256sum | awk \'{print \$1}\' > ${temp_noise_file}",
      path        => $ds_389::path,
      refreshonly => true,
      subscribe   => Exec["stop ${server_id} to create new token"],
      notify      => Exec["Generate password file: ${server_id}"],
    }

    # Create password file.
    exec { "Generate password file: ${server_id}":
      command     => "echo ${root_dn_pass} > ${temp_pass_file}",
      path        => $ds_389::path,
      refreshonly => true,
      notify      => Exec["Create cert DB: ${server_id}"],
    }

    # Create nss db.
    -> exec { "Create cert DB: ${server_id}":
      command     => "certutil -N -d ${instance_path} -f ${temp_pass_file}",
      path        => $ds_389::path,
      refreshonly => true,
      notify      => Ssl_pkey["Generate CA private key: ${server_id}"],
    }

    # Generate the private key for the CA.
    -> ssl_pkey { "Generate CA private key: ${server_id}":
      ensure => 'present',
      path   => $ca_key,
      size   => 4096,
    }

    # Fix permissions of CA private key.
    -> file { "Fix permissions of CA private key: ${server_id}":
      ensure => 'present',
      name   => $ca_key,
      mode   => '0640',
      owner  => $user,
      group  => $group,
    }

    # Create the OpenSSL config template for the CA cert.
    -> file { "Create CA config: ${server_id}":
      ensure  => 'present',
      name    => $ca_conf,
      content => epp('ds_389/openssl_ca.cnf.epp',{
        dc => $facts['networking']['fqdn'],
        cn => $ca_nickname,
      }),
    }

    # Create the CA certificate.
    -> x509_cert { "Create CA cert: ${server_id}":
      ensure      => 'present',
      path        => $ca_cert,
      template    => $ca_conf,
      private_key => $ca_key,
      days        => 3650,
      req_ext     => false,
    }

    # Export CA cert to pkcs12, which is required for import into nss db.
    # TODO: openssl::export::pkcs12 cannot be used, because it does not support
    # a password file (yet).
    -> exec { "Prepare CA cert for import (pkcs12): ${server_id}":
      cwd         => $instance_path,
      command     => "openssl pkcs12 -export -in ${ca_cert} -inkey ${ca_key} -out ${ca_p12} -password file:${temp_pass_file}",
      path        => $ds_389::path,
      refreshonly => true,
      subscribe   => [
        X509_cert["Create CA cert: ${server_id}"],
      ],
    }

    # Import CA cert+key into nss db.
    -> exec { "Import CA cert: ${server_id}":
      cwd         => $instance_path,
      command     => "pk12util -i ${ca_p12} -d sql:${instance_path} -k ${temp_pass_file} -w ${temp_pass_file}",
      path        => $ds_389::path,
      refreshonly => true,
      subscribe   => [
        X509_cert["Create CA cert: ${server_id}"],
      ],
      notify      => [
        Exec["Make server cert and add to database: ${server_id}"],
        Exec["Clean up temp files: ${server_id}"],
        Exec["Add trust for CA: ${server_id}"],
      ],
    }

    # Change nickname to make it clear that this is the CA cert.
    -> exec { "Fix name of imported CA: ${server_id}":
      cwd         => $instance_path,
      command     => "certutil --rename -n \"${ca_nickname} - ${facts['networking']['fqdn']}\" --new-n \"${ca_nickname}\" -d sql:${instance_path}", # lint:ignore:140chars
      path        => $ds_389::path,
      refreshonly => true,
      subscribe   => [
        X509_cert["Create CA cert: ${server_id}"],
      ],
    }

    # Configure trust attributes.
    -> exec { "Add trust for CA: ${server_id}":
      command   => "certutil -M -n \"${ca_nickname}\" -t CT,C,C -d ${instance_path} -f ${temp_pass_file}",
      path      => $ds_389::path,
      unless    => "certutil -L -d ${instance_path} | grep \"${ca_nickname}\" | grep \"CTu,Cu,Cu\"",
      subscribe => [
        X509_cert["Create CA cert: ${server_id}"],
      ],
      notify    => Exec["Export CA cert: ${server_id}"],
    }

    # Export ca cert.
    -> exec { "Export CA cert: ${server_id}":
      cwd     => $instance_path,
      command => "certutil -d ${instance_path} -L -n \"${ca_nickname}\" -a > ${ca_cert}",
      path    => $ds_389::path,
      creates => $ca_cert,
    }

    # Copy ca cert to openldap.
    -> file { "${ds_389::cacerts_path}/${server_id}CA.pem":
      ensure  => file,
      source  => $ca_cert,
      require => Exec["Export CA cert: ${server_id}"],
      notify  => Exec["Rehash cacertdir: ${server_id}"],
    }

    # Create server cert and add to database.
    exec { "Make server cert and add to database: ${server_id}":
      cwd         => $instance_path,
      command     => "certutil -S -n \"${ssl_cert_name}\" -m 101 -s \"cn=${server_host}\" -c \"${ca_nickname}\" -t \"u,u,u\" -v 120 -d ${instance_path} -k rsa -z ${temp_noise_file} -f ${temp_pass_file} ${sans} && sleep 2", # lint:ignore:140chars
      path        => $ds_389::path,
      refreshonly => true,
      notify      => [
        Exec["Set permissions on database directory: ${server_id}"],
        Exec["Clean up temp files: ${server_id}"],
        Exec["Add trust for server cert: ${server_id}"],
      ],
    }

    # Configure trust attributes.
    -> exec { "Add trust for server cert: ${server_id}":
      command => "certutil -M -n \"${ssl_cert_name}\" -t u,u,u -d ${instance_path}",
      path    => $ds_389::path,
      unless  => "certutil -L -d ${instance_path} | grep \"${ssl_cert_name}\" | grep \"u,u,u\"",
      notify  => Exec["Export server cert: ${server_id}"],
    }

    # Set perms on database directory.
    -> exec { "Set permissions on database directory: ${server_id}":
      command     => "chown ${user}:${group} ${instance_path}",
      path        => $ds_389::path,
      refreshonly => true,
    }

    # Remove temp files (passwd and noise).
    -> exec { "Clean up temp files: ${server_id}":
      command     => "rm -f ${temp_noise_file} ${temp_pass_file}",
      path        => $ds_389::path,
      refreshonly => true,
    }
  }

  # Export server cert.
  exec { "Export server cert: ${server_id}":
    cwd     => $instance_path,
    command => "certutil -d ${instance_path} -L -n \"${ssl_cert_name}\" -a > ${server_id}Cert.pem",
    path    => $ds_389::path,
    creates => "${instance_path}/${server_id}Cert.pem",
  }
  -> file { "${ds_389::cacerts_path}/${server_id}Cert.pem":
    ensure => file,
    source => "${instance_path}/${server_id}Cert.pem",
  }

  # Rehash certs.
  ~> exec { "Rehash cacertdir: ${server_id}":
    command     => "${ds_389::cacert_rehash} ${ds_389::cacerts_path}",
    path        => $ds_389::path,
    refreshonly => true,
  }
  ~> exec { "restart ${server_id} to pick up new token":
    command     => "${service_restart_command} ; sleep 2",
    path        => $ds_389::path,
    refreshonly => true,
  }

  # Add schema extensions.
  if $schema_extensions {
    $schema_extensions.each |$filename, $source| {
      ds_389::schema { $filename:
        server_id => $server_id,
        user      => $user,
        group     => $group,
        source    => $source,
        require   => Exec["restart ${server_id} to pick up new token"],
        before    => Service["dirsrv@${server_id}"],
      }
    }
  }

  # Configure SSL.
  ds_389::ssl { $server_id:
    cert_name       => $ssl_cert_name,
    root_dn         => $root_dn,
    root_dn_pass    => $root_dn_pass,
    server_host     => $server_host,
    server_port     => $server_port,
    server_ssl_port => $server_ssl_port,
    user            => $user,
    group           => $group,
    minssf          => $minssf,
    ssl_version_min => $ssl_version_min,
    notify          => Service["dirsrv@${server_id}"],
  }

  # Setup system service for this instance.
  ds_389::service { $server_id: }

  # If we're setting a minimum ssf, pass starttls flag to ldapadd/modify
  if $minssf > 0 {
    $_starttls = true
  }
  else {
    $_starttls = false
  }

  # Manage plugins.
  if $plugins {
    $plugins.each |$plugin_name, $plugin_config| {
      # A hash may contain optional plugin configuration.
      if ($plugin_config =~ Hash) {
        if ('ensure' in $plugin_config) {
          $_plugin_state = $plugin_config['ensure']
        } else {
          $_plugin_state = 'enabled'
        }

        if ('options' in $plugin_config) {
          $_plugin_options = $plugin_config['options']
        } else {
          $_plugin_options = []
        }
      } else {
        $_plugin_state = $plugin_config
        $_plugin_options = []
      }

      ds_389::plugin { $plugin_name:
        ensure       => $_plugin_state,
        options      => $_plugin_options,
        server_id    => $server_id,
        root_dn      => $root_dn,
        root_dn_pass => $root_dn_pass,
        server_host  => $server_host,
        server_port  => $server_port,
        require      => Service["dirsrv@${server_id}"],
        before       => Anchor["${name}_ldif_modify"],
      }
    }
  }

  # Setup replication.
  if $replication {
    ds_389::replication { $server_id:
      bind_dn             => $replication['bind_dn'],
      replication_pass    => $replication['replication_pass'],
      replication_user    => $replication['replication_user'],
      role                => $replication['role'],
      id                  => $replication['id'],
      purge_delay         => $replication['purge_delay'],
      suppliers           => $replication['suppliers'],
      hubs                => $replication['hubs'],
      consumers           => $replication['consumers'],
      excluded_attributes => $replication['excluded_attributes'],
      init_suppliers      => $replication['init_suppliers'],
      init_hubs           => $replication['init_hubs'],
      init_consumers      => $replication['init_consumers'],
      starttls            => $_starttls,
      replica_port        => $replication['replica_port'],
      replica_transport   => $replication['replica_transport'],
      root_dn             => $root_dn,
      root_dn_pass        => $root_dn_pass,
      suffix              => $suffix,
      server_host         => $server_host,
      server_port         => $server_port,
      user                => $user,
      group               => $group,
      require             => Service["dirsrv@${server_id}"],
      before              => Anchor["${name}_ldif_modify"],
    }
  }

  # Configure backup.
  if $backup_enable {
    $_server_protocol = $backup_notls ? {
      true    => 'ldap',
      default => 'ldaps',
    }
    $_server_port = $backup_notls ? {
      true    => $server_port,
      default => $server_ssl_port,
    }

    ds_389::backup { $server_id:
      protocol     => $_server_protocol,
      root_dn      => $root_dn,
      root_dn_pass => $root_dn_pass,
      server_host  => $server_host,
      server_id    => $server_id,
      server_port  => $_server_port,
    }
  }

  anchor { "${name}_ldif_modify":
    require => Service["dirsrv@${server_id}"],
  }

  # ldif modify
  if $modify_ldifs {
    $modify_ldifs.each |$filename, $source| {
      ds_389::modify { $filename:
        server_id    => $server_id,
        root_dn      => $root_dn,
        root_dn_pass => $root_dn_pass,
        server_host  => $server_host,
        server_port  => $server_port,
        starttls     => $_starttls,
        source       => $source,
        user         => $user,
        group        => $group,
        tag          => "${server_id}_modify",
        require      => Anchor["${name}_ldif_modify"],
        before       => Anchor["${name}_ldif_add"],
      }
    }
  }

  anchor { "${name}_ldif_add": }

  # ldif add
  if $add_ldifs {
    $add_ldifs.each |$filename, $source| {
      ds_389::add { $filename:
        server_id    => $server_id,
        root_dn      => $root_dn,
        root_dn_pass => $root_dn_pass,
        server_host  => $server_host,
        server_port  => $server_port,
        starttls     => $_starttls,
        source       => $source,
        user         => $user,
        group        => $group,
        tag          => "${server_id}_add",
        require      => Anchor["${name}_ldif_add"],
        before       => Anchor["${name}_ldif_base_load"],
      }
    }
  }

  anchor { "${name}_ldif_base_load": }

  # ldif base_load
  if $base_load_ldifs {
    $base_load_ldifs.each |$filename, $source| {
      ds_389::add { $filename:
        server_id    => $server_id,
        root_dn      => $root_dn,
        root_dn_pass => $root_dn_pass,
        server_host  => $server_host,
        server_port  => $server_port,
        starttls     => $_starttls,
        source       => $source,
        user         => $user,
        group        => $group,
        tag          => "${server_id}_base_load",
        require      => Anchor["${name}_ldif_base_load"],
      }
    }
  }
}
