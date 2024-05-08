# LDAP Keycloak Bridge

A simple LDAP server modeling a user directory by answering LDAP queries with user information fetched from a Keycloak server.
The LDAP clients will authenticate with the credentials of a keycloak client and are thus shown the users this keycloak client has access to.

Note that the API does only support read operations and offers a limited subset of the LDAP protocol only:
- We do not implement alias dereferencing
- We do not have any operational attributes ("+")
- We do not honour the size limit imposed by the client or perform any pagination.
- We ignore the ctrl parameter.

## Building

First, the software needs to be build:

```bash
cargo build --release
```

It is important to build the release version for production as the performance is significantly better when using the release build.

### Running the API

This API is designed to only run via TLS (LDAPS). Therefore, you will need to generate a server certificate.

For testing purposes, this can be done by running `openssl req -x509 -newkey rsa:2048 -nodes -keyout ldap_keycloak_bridge.key.pem -out ldap_keycloak_bridge.crt.pem`.
For production, you should request a certificate for example using [LetsEncrypt](https://letsencrypt.org/).

The API can be started by running

```bash
target/release/ldap_keycloak_bridge
```

It should now be available at `ldaps://0.0.0.0:3000`. To see all available configuration options, use the `--help` flag.

If you want to run the API under the typical LDAPS port (636), you will need to have root permissions or
[use some other way to bind to a privileged port](https://stackoverflow.com/questions/413807/is-there-a-way-for-non-root-processes-to-bind-to-privileged-ports-on-linux).

### Manual testing

The API can be tested manually using [Apache Directory Studio](https://directory.apache.org/studio/).

Make sure you have access to a running Keycloak instance and that the realm you configured with the API exists in the Keycloak.
As LDAP bind authentication, you should configure the client credentials of a Keycloak service account that needs to have access to the realm
and has the `view-users` service account role assigned.
Otherwise, the API will report an authentication error as it is not able to access user information, even if the client credentials are valid.
Make sure there are actually any users in the realm, otherwise, you won't get any results from the API :)
