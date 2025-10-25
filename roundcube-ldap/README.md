# Roundcube LDAP adapter for shared address book

## Run server

`roundcube-ldap  --disable-ldaps --keycloak-address https://keycloak.giz.berlin/auth --session-first-answer-delay-millis 0`

## Configure in Roundcube

Add to your Roundcube `config.php` the following lines:

```php
// See https://github.com/roundcube/roundcubemail/blob/master/config/defaults.inc.php
$config['ldap_public']['Keycloak'] = [
  'name' => 'Keycloak',
  'hosts' => array('your-instance:3000'),
  'ldap_version'  => 3,
  'network_timeout' => 1,
  'user_specific' => false,
  'base_dn'       => 'dc=giz,dc=berlin',
  'bind_dn'       => '<your-client-id>',
  'bind_pass'     => '<your-client-secret>',
  'search_base_dn' => '',
  'search_filter'  => '',
  'search_bind_dn' => '',
  'search_bind_pw' => '',
  'domain_base_dn' => '',
  'domain_filter'  => '',
  'search_bind_attrib' => [],
  'search_dn_default' => '',
  'auth_cid'       => '',
  'auth_method'    => '',
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
  ],
  'sub_fields' => [],
  'sort'           => 'displayName',
  'scope'          => 'sub',
  'filter'         => '',
  'fuzzy_search'   => true,  // server allows wildcard search
];
```