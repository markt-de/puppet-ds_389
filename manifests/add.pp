# @summary Adds an ldif file to a 389 ds instance.
#
# @example Adding an ldif file with required params.
#   ds_389::add { 'add_example_1':
#     server_id    => 'foo',
#     source       => 'puppet:///path/to/file.ldif',
#     root_dn      => 'cn=Directory Manager',
#     root_dn_pass => 'supersecure',
#   }
#
# @example Adding an ldif file when using a template.
#   ds_389::add { 'add_example_2':
#     server_id    => 'foo',
#     content      => epp('profiles/template.ldif.epp'),
#     root_dn      => 'cn=Directory Manager',
#     root_dn_pass => 'supersecure',
#   }
#
# @example Adding an ldif file when using all params.
#   ds_389::add { 'add_example_3':
#     server_id    => 'foo',
#     source       => '/path/to/file.ldif',
#     root_dn      => 'cn=Directory Manager',
#     root_dn_pass => 'supersecure',
#     server_host  => 'foo.example.com',
#     server_port  => 1389,
#     user         => 'custom_user',
#     group        => 'custom_group',
#   }
#
# @param content
#   The content value to use for the ldif file. Required, unless providing the source.
#
# @param group
#   The group of the created ldif file. Default: `$ds_389::group`
#
# @param protocol
#   The protocol to use when calling ldapadd. Default: 'ldap'
#
# @param root_dn_pass
#   The password to use when calling ldapadd. Required.
#
# @param root_dn
#   The bind DN to use when calling ldapadd. Required.
#
# @param server_host
#   The host to use when calling ldapadd. Default: `$facts['networking']['fqdn']`
#
# @param server_id
#   The 389 ds instance name. Required.
#
# @param server_port
#   The port to use when calling ldapadd. Default: 389
#
# @param source
#   The source path to use for the ldif file. Required, unless providing the content.
#
# @param starttls
#   Whether to use StartTLS when calling ldapadd. Default: false
#
# @param user
#   The owner of the created ldif file. Default: `$ds_389::user`
#
define ds_389::add (
  String $server_id,
  String $root_dn,
  Variant[String,Sensitive[String]] $root_dn_pass,
  Optional[String] $content = undef,
  Optional[String] $source = undef,
  String $server_host = $facts['networking']['fqdn'],
  Integer $server_port = 389,
  Enum['ldap','ldaps'] $protocol = 'ldap',
  Boolean $starttls = false,
  String $user = $ds_389::user,
  String $group = $ds_389::group,
) {
  include ds_389

  if !$content and !$source {
    fail('ds_389::add requires a value for either $content or $source')
  }

  if $starttls {
    $_opts = 'ZxH'
  }
  else {
    $_opts = 'xH'
  }

  file { "/etc/dirsrv/slapd-${server_id}/${name}.ldif":
    ensure  => file,
    mode    => '0440',
    owner   => $user,
    group   => $group,
    content => $content,
    source  => $source,
  }
  -> exec { "Add ldif ${name}: ${server_id}":
    command => "ldapadd -${_opts} ${protocol}://${server_host}:${server_port} -D \"${root_dn}\" -w ${root_dn_pass} -f /etc/dirsrv/slapd-${server_id}/${name}.ldif && touch /etc/dirsrv/slapd-${server_id}/${name}.done", # lint:ignore:140chars
    path    => $ds_389::path,
    creates => "/etc/dirsrv/slapd-${server_id}/${name}.done",
  }
}
