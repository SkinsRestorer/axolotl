use std::time::Duration;

use reqwest::{Client, ClientBuilder};

pub(crate) fn builder(request_timeout: Duration) -> ClientBuilder {
    Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(request_timeout)
}
