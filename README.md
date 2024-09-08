# LDAP Keycloak Bridge

A simple LDAP server modeling a user directory by answering LDAP queries with user information fetched from a Keycloak server.
The LDAP clients will authenticate with the credentials of a keycloak client and are thus shown the users this keycloak client has access to.

Note that the API does only support read operations and offers a limited subset of the LDAP protocol only:
- We do not implement alias dereferencing
- We do not have any operational attributes ("+")
- We do not honour the size limit imposed by the client or perform any pagination.
- We ignore the ctrl parameter.

## Use Cases

Currently, this service is intended to provide the following use cases:

- [implemented] providing a list of E-Mail addresses to printers
- providing an address book, for example to mail clients
- informing the NextCloud about active users, so that deactivated users can be removed
- informing the locking system about user roles/group memberships

### Creating a binary for a new use case

To create a binary for a new use case, create a new subfolder and initialize a new cargo project with a local dependency to `giz-ldap-lib`
and add it to the [workspace members](Cargo.toml).
There, you should create a new implementation of the `giz-ldap-lib::search::KeycloakUserAttributeExtractor` trait, which allows you to configure
which Keycloak user attributes will be exposed by the LDAP user entries.

As the LDAP library will handle argument parsing and logging, your main function should simply look like this:
```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    giz-ldap-lib::server::start_ldap_server(Box::new(YourKeycloakUserAttributeExtractor{})).await
}
```

See [the printer-specific implementation](printer-ldap) for an example.

## Building

First, the software needs to be build:

```bash
cargo build --release
```

It is important to build the release version for production as the performance is significantly better when using the release build.

### Running the API

This API is designed to only run via TLS (LDAPS). Therefore, you will need to generate a server certificate.

For testing purposes, this can be done by running `openssl req -x509 -newkey rsa:4096 -nodes -keyout ldap_keycloak_bridge.key.pem -out ldap_keycloak_bridge.crt.pem -subj "/C=DE/CN=127.0.0.1"`.
For production, you should request a certificate for example using [LetsEncrypt](https://letsencrypt.org/).

The API can be started by running

```bash
target/release/{target_binary}
```

where `target_binary` is one of the use-case specific binaries build, for example `printer-ldap`.

The API should now be available at `ldaps://0.0.0.0:3000`. To see all available configuration options, use the `--help` flag.

If you want to run the API under the typical LDAPS port (636), you will need to have root permissions or
[use some other way to bind to a privileged port](https://stackoverflow.com/questions/413807/is-there-a-way-for-non-root-processes-to-bind-to-privileged-ports-on-linux).

### Manual testing

By default, the API expects to be pointed at a local Keycloak instance that can be started by running `docker compose -f e2e-test/compose.yml up keycloak`. This will start a keycloak instance that already has a preconfigured realm `giz_oidc` with a couple of users and groups in it. You may add more users by editing the [bootstrap file](./e2e-test/keycloak_realm_config/giz_oidc.json) or via the Keycloak Admin console available at `localhost:8080` ([credentials](docker-compose.yml)). (Note that if you do so via the bootstrap file, make sure to create a new container, because realms will not be loaded from the file if they already exist)

The API can be tested manually using [Apache Directory Studio](https://directory.apache.org/studio/). You can also perform LDAP requests via the command line using the `ldapsearch` utility. Example:

```bash
LDAPTLS_CACERT=ldap_keycloak_bridge.crt.pem ldapsearch -H ldaps://127.0.0.1:3000 -x -LLL -D ldap_bridge -w ldap_bridge_secret -b dc=giz,dc=berlin -s subtree '(objectClass=*)' +
```

As LDAP bind authentication, you should configure the client credentials of a Keycloak service account that needs to have access to the realm and has the `view-users` service account role assigned. Otherwise, the API will report an authentication error as it is not able to access user information, even if the client credentials are valid.

The default keycloak instance will have a client `ldap_bridge` with secret `ldap_bridge_secret` properly set up.
