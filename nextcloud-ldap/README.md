# Nextcloud LDAP

The `nextcloud-ldap` use case provides an LDAP proxy to Keycloak which exports the attributes required by Nextcloud when you use LDAP.

**Note**: This use case does not support validating passwords of the users. To allow users to log in you should use [Login via OIDC](#login-via-oidc).

## Configuration

1. Before configuring your Nextcloud ensure that the Nextcloud LDAP use case is running and that you have created a client in Keycloak similar to the other LDAP use cases.
1. Enable `LDAP user and group backend` app in your Nextcloud.
1. Configure the LDAP integration by following the official ["User authentication with LDAP"](https://docs.nextcloud.com/server/latest/admin_manual/configuration_user/user_auth_ldap.html) docs. You'll have to make the following settings:
    - **Server**
        - **LDAP Port**: This is `3000` by default, unless you change the `bind-address` setting.
        - **User DN**: Your Keycloak client ID
        - **Password**: Your Keycloak client secret
        - **Base DN**: The base DN you configured for the program which is `dc=giz,dc=berlin` by default
    - **Users**
        - **LDAP Query**: Hit `Edit LDAP Query` and enter `(&(&(objectclass=inetOrgPerson)(enabled=true)))` to ensure that only users which are enabled in Keycloak will be fetched.
    - **Login Attributes**
        - Hit `Edit LDAP Query` and enter `(&(&(|(objectclass=inetOrgPerson)))(&(entryuuid=%uid)(enabled=true)))` to ensure that only users which are enabled are allowed to log in. For example, this query is used when the OIDC plugin queries the user from the LDAP backend.
    - **Groups**
        - **Only these object classes**: Nextcloud does not import groups by default so select `groupOfUniqueNames` here and Nextcloud will import them just fine.
    - **Advanced**
        - **Directory Settings**
            - **Disable users missing from LDAP**: Activate this to ensure that users missing from the LDAP, e.g. because they were disabled or deleted in Keycloak, are disabled in the Nextcloud.
            - **Group Display Name Field**: Set this to `fullname` to show the groups including their full path in Keycloak
1. In both the **Users** and the **Groups** tab, hit the "Verify settings and count" button and verify that the number of entities found matches with what you have in your Keycloak. Additionally, visit the "Accounts" page to find all of your users and groups.

### User Deactivation

Since we filter the LDAP for users with `enabled=true`, users which are deactivated in Keycloak won't be shown in the Nextcloud.
If you deactivate a user which had an account in the Nextcloud already, their user account will be deactivated once Nextcloud updates its users from the LDAP again and they are marked as `deleted`.
All app passwords of the user will be removed as well such that apps like the Nextcloud desktop app won't be able to log in as well.
The user itself won't be deleted unless you delete them manually.
Thus, if you enable the user in Keycloak again, the user will be enabled in Nextcloud again and will have access to all of their old files.

See the [LDAP user cleanup](https://docs.nextcloud.com/server/latest/admin_manual/configuration_user/user_auth_ldap_cleanup.html) docs for more information.
You may want to tweak the `ldapUserCleanupInterval` and the `cleanUpJobChunkSize` settings to ensure a faster deactivation.

## Login via OIDC

In this section we'll configure the [OpenID Connect Login](https://github.com/pulsejet/nextcloud-oidc-login) plugin to work with the LDAP backend correctly.
Conveniently, this plugin supports having LDAP as the primary user backend which is why we chose to use it.
In your Nextcloud `config.php`, set the following configuration values in addition to the other OIDC configuration values:

```php
'oidc_login_proxy_ldap' => true,
'oidc_login_attributes' => array (
    'ldap_uid' => 'sub',
),
```

And with that your users are able to log in via OIDC with your Keycloak and their data will be updated periodically by the Nextcloud via LDAP.
