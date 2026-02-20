# Roundcube LDAP adapter for shared address book

## Run server

`roundcube-ldap --config example-config.toml`

For configuration options, please check out [example-config.toml](./example-config.toml).

## Configuration

This section guides you through the necessary configuration required for both components Keycloak and Roundcube.

### Keycloak

1. Create a new confidential client
1. Deactivate all authentication mechanisms except `Service-Account-Roles`
1. Add these roles to the Service-Account-Roles
    1. `view-users` from `realm-management`

### Roundcube

Add to your Roundcube `config.php` the following lines:

```php
// See https://github.com/roundcube/roundcubemail/blob/master/config/defaults.inc.php
$config['ldap_public']['Keycloak'] = [
  'name' => 'Keycloak',
  'hosts' => array('<your-ldap-proxy-host>:3000'),
  'ldap_version'  => 3,
  'network_timeout' => 1,
  'user_specific' => false,
  'base_dn'       => 'dc=giz,dc=berlin',
  'bind_dn'       => '<your-client-id>',
  'bind_pass'     => '<your-client-secret>',
  // Indicates if the addressbook shall be hidden from the list.
  // With this option enabled you can still search/view contacts.
  'hidden'        => false,
  // Indicates if the addressbook shall not list contacts but only allows searching.
  'searchonly'    => false,
  // This is a read-only LDAP server
  'writable'       => false,
  'LDAP_Object_Classes' => ['top', 'inetOrgPerson'],
  'LDAP_rdn'       => 'cn',
  // The attributes used when searching with "All fields" option
  // If empty, attributes for name, surname, firstname and email fields will be used
  'search_fields'   => ['mail', 'displayName', 'givenName', 'surname', 'jobtitle'],
  'fieldmap' => [
    // Roundcube  => LDAP:limit
    'name'        => 'displayName',
    'surname'     => 'surname',
    'firstname'   => 'givenName',
    'jobtitle'    => 'username',
    'email'       => 'mail:*',
    'uid'         => 'cn',
  ],
  'sub_fields' => [],
  'sort'           => 'displayName',
  'scope'          => 'sub',
  'filter'         => '(objectClass=inetOrgPerson)',
  // server allows wildcard search
  'fuzzy_search'   => true,

  'groups'  => [
    'base_dn'           => '',
    'scope'             => 'sub',
    'filter'            => '(objectClass=groupOfUniqueNames)',
    'object_classes'    => ['top', 'groupOfUniqueNames'],
    'member_attr'       => 'uniqueMember',
    'name_attr'         => 'fullName',
    'email_attr'        => 'mail',
    'member_filter'     => '(objectClass=inetOrgPerson)',
    'vlv'               => false,
    'class_member_attr' => [
      'groupofnames'       => 'member',
      'groupofuniquenames' => 'uniquemember'
    ],
  ],
];

// This cache type is important as with the db cache, some weird issues (old cache entries) might arise
$config['ldap_cache'] = 'apcu';
$config['ldap_cache_ttl'] = '1m';

$config['autocomplete_addressbooks'] = ['sql', 'Keycloak'];
```
