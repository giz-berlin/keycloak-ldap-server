# LDAP Keycloak Bridge

A simple LDAP server modeling a user directory by answering LDAP queries with user information fetched from a Keycloak server.
The LDAP clients will authenticate with the credentials of a keycloak client and are thus shown the users this keycloak client has access to.

Note that the API does only support read operations and offers a limited subset of the LDAP protocol only:
- We do not implement alias dereferencing
- We do not have any operational attributes ("+")
- We do not honour the size limit imposed by the client or perform any pagination.
- We ignore the ctrl parameter.

## Disclaimer

This projects implements caching to vastly reduce the number of required Keycloak queries. For this reason, it may take a couple of seconds before changes in the Keycloak become visible through our API (how long exactly depends on how the bridge is configured).

WARNING: Due to caching, when changing the credentials of a client in the keycloak, the old password will still be accepted until the cache entry is refreshed, see [`KeycloakClientLdapCache::check_password` in `cache.rs`](ldap-lib/src/caching/cache.rs). Remember to restart the server or wait the specified refresh interval before using the new password.

## Use Cases

Currently, this service is intended to provide the following use cases:

- [implemented] providing a list of E-Mail addresses to printers
- providing an address book, for example to mail clients
- [implemented] informing the NextCloud about active users, so that deactivated users can be removed
- informing the locking system about user roles/group memberships

### Creating a binary for a new use case

To create a binary for a new use case, create a new subfolder and initialize a new cargo project with a local dependency to `giz-ldap-lib`
and add it to the [workspace members](Cargo.toml).
There, you should create a new implementation of the `giz_ldap_lib::interface::Target` trait, which allows you to configure
which source (Keycloak) attributes will be exposed by the LDAP user and group entries.

As the LDAP library will handle argument parsing and logging, your main function should simply look like this:
```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let include_group_info = true;
   giz_ldap_lib::server::start_ldap_server::<YourNewTarget>(include_group_info).await
}
```

See [the printer-specific implementation](printer-ldap) for an example.

NOTE: In order to prevent ambiguity regarding subgroups (to differentiate between a group `Test/Test` and a group `Test` with a subgroup `Test`),
this service REPLACES all `/` characters in a group name with `_`.

In order to build a docker container for your new use-case binary, modify the `pack` step in the `.gitlab-ci.yml` accordingly.

### Running the API

### Configuration

Configuration is handled via a toml file, which can be passed via the `--config` option to the binary.

Available configuration options are:

```toml
[source.keycloak_api]
url = "https://keycloak.giz.berlin/auth"
realm = "giz-playground"
# Optional, number of users fetched per request
fetch_users_num = 20

# Optional
[sentry]
dsn = "your-dsn"
environment = "your-environment-this-binary-is-running-in"

[ldap_server]
# Optional, the base point of our LDAP tree
base_distinguished_name = "dc=giz,dc=berlin"
# Optional, the name of the organization as shown by the LDAP base entry
organization_name = "giz.berlin"
# Optional, bind address with port
bind_address = "[::]:3000"
# Optional, whether to disable the secure LDAP access and enable unencrypted access
disable_ldaps = false
# Optional, the TLS certificate used by the LDAP server if LDAPS is enabled
certificate: "certificates/ldap.pem"
# Optional, the TLS certificate private key used by the LDAP server if LDAPS is enabled
certificate_key: "certificates/ldap.key"

# Optional, time to wait before sending first response in a session in milliseconds because some client implementations will miss the first response if it comes in too fast.
session_first_answer_delay_millis = 0

# Optional, how often to update entries in the LDAP cache in seconds. WARNING: If client credentials are changed in the keycloak, the old secret/password will still stay valid for this long!
cache_update_interval_secs = 60

# How long to wait in seconds before pruning LDAP cache entries that are not being accessed.
cache_entry_max_inactive_secs = 3600

[target]
# Depending on the API target (printer, Roundcube, Nextcloud), different target configuration options are available. Please check the corresponding Readme for their options.
```

This API can run with or without TLS (LDAPS), depending on whether `disable-ldaps` is configured. If you want to run it via TLS, you will need to generate a server certificate.

For testing purposes, this can be done by running (note that the `certificates` folder is the target location)

```shell
openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout certificates/ldap_keycloak_bridge.key.pem \
    -out certificates/ldap_keycloak_bridge.crt.pem \
    -subj "/C=DE/CN=127.0.0.1"
```

For production, you should request a certificate for example using [LetsEncrypt](https://letsencrypt.org/).

This repository contains multiple use-case specific binaries, for example `printer-ldap`.

You can start the API using one of the following ways.
Substitute `{target_binary}` with the name of the use-case specific binary you want to run.

- **Using the official Docker image**:

    ```shell
    docker run --init -it --rm -p 0.0.0.0:3000:3000 -v ./certificates:/certificates --name ldap-server \
        dr.rechenknecht.net/giz/keycloak/keycloak-ldap-server/main/{target_binary}:latest
    ```

- **Building the binary locally**:

  ```shell
  cargo build --release
  ```

  It is important to build the release version for production as the performance is significantly better when using the release build.

  You can now run the binary with

  ```shell
  target/release/{target_binary}
  ```

The API should now be available at `ldaps://0.0.0.0:3000`. To see all available, please check out [config.rs](./ldap-lib/src/config.rs).

If you want to run the API under the typical LDAPS port (636), you will need to have root permissions or
[use some other way to bind to a privileged port](https://stackoverflow.com/questions/413807/is-there-a-way-for-non-root-processes-to-bind-to-privileged-ports-on-linux).

### Logging configuration

The default log level of this API is INFO, while log message of crates we depend on are shown starting with WARN.
You can enable more verbose logging via the `-v` flag (DEBUG), or the `-vv` flag (TRACE).

Additionally, you may configure the logging (for the whole API, certain submodules or dependencies)
on a more granular level using the `RUST_LOG` environment variable
(see [here](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) for required syntax.)

### Manual testing

By default, the API expects to be pointed at a local Keycloak instance that can be started by running `docker compose -f e2e-test/compose.yml up keycloak`. This will start a keycloak instance that already has a preconfigured realm `giz_oidc` with a couple of users and groups in it. You may add more users by editing the [bootstrap file](./e2e-test/keycloak_realm_config/giz_oidc.json) or via the Keycloak Admin console available at `localhost:8080` ([credentials](docker-compose.yml)). (Note that if you do so via the bootstrap file, make sure to create a new container, because realms will not be loaded from the file if they already exist)

The API can be tested manually using [Apache Directory Studio](https://directory.apache.org/studio/). You can also perform LDAP requests via the command line using the `ldapsearch` utility. Example:

```shell
LDAPTLS_CACERT=ldap_keycloak_bridge.crt.pem ldapsearch -H ldaps://127.0.0.1:3000 -x -LLL -D ldap_bridge -w ldap_bridge_secret -b dc=giz,dc=berlin -s subtree '(objectClass=*)' +
```

As LDAP bind authentication, you should configure the client credentials of a Keycloak service account that needs to have access to the realm and has the `view-users` service account role assigned. Otherwise, the API will report an authentication error as it is not able to access user information, even if the client credentials are valid.

The default keycloak instance will have a client `ldap_bridge` with secret `ldap_bridge_secret` properly set up.

Note that the API will only return groups if the use-case-specific binary you run is starting the LDAP server with `include_group_info=true`.
