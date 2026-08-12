# Zammad LDAP

The `zammad-ldap` use case provides an LDAP proxy to Keycloak which exports the attributes required by Zammad when you use LDAP.

**Note**: This use case does not support validating passwords of the users. To allow users to log in you should use [Login via OIDC](https://admin-docs.zammad.org/en/latest/settings/security/third-party/openid-connect.html) or [Login via SAML](https://admin-docs.zammad.org/en/latest/settings/security/third-party/saml.html).

## Configuration

1. Before configuring your Zammad ensure that the Zammad LDAP use case is running and that you have created a client in Keycloak similar to the other LDAP use cases.
1. Go to `Administration > System > Integrations > LDAP`.
1. Turn on LDAP sync with the button on the top left.
1. Click `New Source`.
1. Choose a name for the source and set the domain of your LDAP bridge host. Then click `Connect`.
1. Set `dc=giz,dc=berlin` as the `Base DN`. Set the Keycloak client's name as `Bind User` and its client secret as `Bind Password`.
1. Configure the matching of LDAP attributes to Zammad attributes to your liking. Make sure to configure `mail` as the source for `Login`.
1. Select which Keycloak groups (identified by their ID) provide which Role. Normally you want to include the hierarchy to allow users of a subgroup to also get the Role associated with the parent group.
1. Complete the dialog and wait for the sync to finish.

### User Deactivation

Since we filter the LDAP for users with `enabled=true`, users which are deactivated in Keycloak won't be shown in Zammad.
If you deactivate a user which had an account in Zammad already, their user account will be deactivated once Zammad updates its users from the LDAP again.
The user itself won't be deleted unless you delete them manually.
Thus, if you enable the user in Keycloak again, the user will be enabled in Zammad again and will have access to all of their old tickets.
