use anyhow::{anyhow, Context};
use openssl::{
    pkey::{PKeyRef, Private},
    ssl::{SslAcceptor, SslFiletype, SslMethod},
};

const RSA_MIN_KEY_SIZE_BITS: u32 = 4096;
const EC_MIN_KEY_SIZE_BITS: i32 = 256;

/// From the server configuration, generate an OpenSSL acceptor that we can use
/// to build our sockets for HTTPS/LDAPS.
pub fn setup_tls(certificate: std::path::PathBuf, certificate_key: std::path::PathBuf) -> anyhow::Result<SslAcceptor> {
    // Signing algorithm minimums are enforced by the SSLAcceptor - it won't start up with a sha1-signed cert.
    // https://wiki.mozilla.org/Security/Server_Side_TLS
    let mut ssl_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    ssl_builder
        .set_certificate_chain_file(certificate)
        .context("Failed to access certificate chain file?")?;
    ssl_builder
        .set_private_key_file(certificate_key, SslFiletype::PEM)
        .context("Failed to access private key file?")?;
    ssl_builder
        .check_private_key()
        .context("Certificate private key does not correspond to certificate?")?;

    let acceptor = ssl_builder.build();

    // let's enforce some TLS minimums!
    let privkey = acceptor.context().private_key().ok_or(anyhow!("Unable to access private key"))?;
    check_privkey_minimums(privkey)?;

    Ok(acceptor)
}

/// Ensure we're enforcing safe minimums for TLS keys
pub fn check_privkey_minimums(privkey: &PKeyRef<Private>) -> anyhow::Result<()> {
    if let Ok(key) = privkey.rsa() {
        if key.size() < (RSA_MIN_KEY_SIZE_BITS / 8) {
            anyhow::bail!("TLS RSA key is less than {} bits!", RSA_MIN_KEY_SIZE_BITS)
        }
    } else if let Ok(key) = privkey.ec_key() {
        if key.private_key().num_bits() < EC_MIN_KEY_SIZE_BITS {
            anyhow::bail!("TLS EC key is less than {} bits!", EC_MIN_KEY_SIZE_BITS)
        }
    } else {
        anyhow::bail!("TLS key is not RSA or EC, cannot check minimums!");
    }

    Ok(())
}
