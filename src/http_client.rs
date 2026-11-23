use std::time::Duration;

use reqwest::{Client, ClientBuilder};

/// Installs `ring` as the process-wide rustls crypto provider.
///
/// reqwest is built without a provider, so a client cannot be built before
/// this runs. Calling it more than once is harmless.
fn install_crypto_provider() {
    // An error only means that a provider is already installed.
    let _already_installed = rustls::crypto::ring::default_provider().install_default();
}

pub(crate) fn builder(request_timeout: Duration) -> ClientBuilder {
    install_crypto_provider();
    Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(request_timeout)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::builder;

    #[test]
    fn builds_https_clients_with_the_ring_provider() {
        let client = builder(Duration::from_secs(1)).https_only(true).build();
        assert!(client.is_ok(), "the HTTPS client should build: {client:?}");
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "building a client should install the crypto provider"
        );
    }
}
