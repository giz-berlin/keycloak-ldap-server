# LDAP Keycloak Bridge

An API that translates and forwards LDAP requests to Keycloak.

## Building

```bash
cargo build --release
```

It is important to build the release version of this software for production as the performance is better by a factor of at least 10 when using the release build.

### Run API

```bash
target/release/ldap_keycloak_bridge
```

The API should now be available at `ldaps://0.0.0.0:3000`
