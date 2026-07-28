use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const LATENCY_BUCKET_UPPER_BOUNDS_MS: [u64; 14] = [
    5,
    10,
    25,
    50,
    100,
    250,
    500,
    1_000,
    2_500,
    5_000,
    10_000,
    30_000,
    60_000,
    u64::MAX,
];
const MAX_TRACKED_CLIENTS: usize = 100_000;

#[derive(Debug)]
pub struct Metrics {
    requests: AtomicU64,
    successful_responses: AtomicU64,
    redirects: AtomicU64,
    client_errors: AtomicU64,
    server_errors: AtomicU64,
    job_requests: AtomicU64,
    cape_requests: AtomicU64,
    health_requests: AtomicU64,
    other_requests: AtomicU64,
    unattributed_requests: AtomicU64,
    mineskin_requests: AtomicU64,
    mineskin_errors: AtomicU64,
    mineskin_rate_limits: AtomicU64,
    bytes_received_from_mineskin: AtomicU64,
    request_latency: LatencyHistogram,
    mineskin_latency: LatencyHistogram,
    upload: EndpointMetrics,
    decrypt: EndpointMetrics,
    client_requests: Mutex<HashMap<IpAddr, u64>>,
    started_at: Instant,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            requests: AtomicU64::new(0),
            successful_responses: AtomicU64::new(0),
            redirects: AtomicU64::new(0),
            client_errors: AtomicU64::new(0),
            server_errors: AtomicU64::new(0),
            job_requests: AtomicU64::new(0),
            cape_requests: AtomicU64::new(0),
            health_requests: AtomicU64::new(0),
            other_requests: AtomicU64::new(0),
            unattributed_requests: AtomicU64::new(0),
            mineskin_requests: AtomicU64::new(0),
            mineskin_errors: AtomicU64::new(0),
            mineskin_rate_limits: AtomicU64::new(0),
            bytes_received_from_mineskin: AtomicU64::new(0),
            request_latency: LatencyHistogram::default(),
            mineskin_latency: LatencyHistogram::default(),
            upload: EndpointMetrics::default(),
            decrypt: EndpointMetrics::default(),
            client_requests: Mutex::new(HashMap::new()),
            started_at: Instant::now(),
        }
    }
}

impl Metrics {
    pub fn record_request(
        &self,
        path: &str,
        status: u16,
        client_ip: Option<IpAddr>,
        latency: Duration,
    ) {
        let mut client_requests = self.lock_client_requests();
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.request_latency.record(latency);

        match status {
            200..=299 => {
                self.successful_responses.fetch_add(1, Ordering::Relaxed);
            }
            300..=399 => {
                self.redirects.fetch_add(1, Ordering::Relaxed);
            }
            400..=499 => {
                self.client_errors.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.server_errors.fetch_add(1, Ordering::Relaxed);
            }
        }

        self.record_endpoint(path, status, latency);

        if let Some(count) = client_ip.and_then(|client_ip| client_requests.get_mut(&client_ip)) {
            *count = count.saturating_add(1);
        } else if let Some(client_ip) =
            client_ip.filter(|_| client_requests.len() < MAX_TRACKED_CLIENTS)
        {
            client_requests.insert(client_ip, 1);
        } else {
            self.unattributed_requests.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn begin_mineskin_request(&self) {
        self.mineskin_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_mineskin_response_bytes(&self, bytes: usize) {
        self.bytes_received_from_mineskin
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub fn finish_mineskin_request(&self, latency: Duration, failed: bool, rate_limited: bool) {
        self.mineskin_latency.record(latency);
        if failed {
            self.mineskin_errors.fetch_add(1, Ordering::Relaxed);
        }
        if rate_limited {
            self.mineskin_rate_limits.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        let client_requests = self.lock_client_requests();
        MetricsSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            successful_responses: self.successful_responses.load(Ordering::Relaxed),
            redirects: self.redirects.load(Ordering::Relaxed),
            client_errors: self.client_errors.load(Ordering::Relaxed),
            server_errors: self.server_errors.load(Ordering::Relaxed),
            job_requests: self.job_requests.load(Ordering::Relaxed),
            cape_requests: self.cape_requests.load(Ordering::Relaxed),
            health_requests: self.health_requests.load(Ordering::Relaxed),
            other_requests: self.other_requests.load(Ordering::Relaxed),
            unattributed_requests: self.unattributed_requests.load(Ordering::Relaxed),
            mineskin_requests: self.mineskin_requests.load(Ordering::Relaxed),
            mineskin_errors: self.mineskin_errors.load(Ordering::Relaxed),
            mineskin_rate_limits: self.mineskin_rate_limits.load(Ordering::Relaxed),
            bytes_received_from_mineskin: self.bytes_received_from_mineskin.load(Ordering::Relaxed),
            request_latency: self.request_latency.snapshot(),
            mineskin_latency: self.mineskin_latency.snapshot(),
            upload: self.upload.snapshot(),
            decrypt: self.decrypt.snapshot(),
            client_requests: client_requests.clone(),
            uptime: self.started_at.elapsed(),
            report_period: Duration::ZERO,
        }
    }

    pub fn acknowledge_client_requests(&self, snapshot: &MetricsSnapshot) {
        let mut requests = self.lock_client_requests();
        for (client_ip, acknowledged) in &snapshot.client_requests {
            if let Some(current) = requests.get_mut(client_ip) {
                *current = current.saturating_sub(*acknowledged);
            }
        }
        requests.retain(|_, count| *count > 0);
    }

    fn lock_client_requests(&self) -> MutexGuard<'_, HashMap<IpAddr, u64>> {
        self.client_requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn record_endpoint(&self, path: &str, status: u16, latency: Duration) {
        match path {
            "/mineskin/skins" => self.upload.record(status, latency),
            "/mineskin/decrypt-url" => self.decrypt.record(status, latency),
            "/mineskin/capes" | "/mineskin/cape-support" => {
                self.cape_requests.fetch_add(1, Ordering::Relaxed);
            }
            "/health" => {
                self.health_requests.fetch_add(1, Ordering::Relaxed);
            }
            _ if path.starts_with("/mineskin/jobs/") => {
                self.job_requests.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.other_requests.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LatencySnapshot {
    buckets: [u64; LATENCY_BUCKET_UPPER_BOUNDS_MS.len()],
    total_micros: u64,
}

impl LatencySnapshot {
    fn since(&self, previous: &Self) -> Self {
        Self {
            buckets: std::array::from_fn(|index| {
                self.buckets
                    .get(index)
                    .copied()
                    .unwrap_or_default()
                    .saturating_sub(previous.buckets.get(index).copied().unwrap_or_default())
            }),
            total_micros: self.total_micros.saturating_sub(previous.total_micros),
        }
    }

    #[must_use]
    pub(crate) fn count(&self) -> u64 {
        self.buckets.iter().sum()
    }

    #[must_use]
    pub(crate) fn average(&self) -> Duration {
        let count = self.count();
        if count == 0 {
            return Duration::ZERO;
        }

        Duration::from_micros(self.total_micros / count)
    }

    #[must_use]
    pub(crate) fn percentile(&self, percentile: u64) -> Duration {
        let count = self.count();
        if count == 0 {
            return Duration::ZERO;
        }
        let target = count
            .saturating_mul(percentile)
            .div_ceil(100)
            .clamp(1, count);
        let mut observed = 0_u64;
        for (index, bucket_count) in self.buckets.iter().enumerate() {
            observed = observed.saturating_add(*bucket_count);
            if observed >= target {
                let upper_bound = LATENCY_BUCKET_UPPER_BOUNDS_MS
                    .get(index)
                    .copied()
                    .unwrap_or(u64::MAX);
                return if upper_bound == u64::MAX {
                    Duration::from_millis(60_001)
                } else {
                    Duration::from_millis(upper_bound)
                };
            }
        }

        Duration::from_millis(60_001)
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct EndpointSnapshot {
    pub(crate) requests: u64,
    pub(crate) successful_responses: u64,
    pub(crate) client_errors: u64,
    pub(crate) server_errors: u64,
    pub(crate) latency: LatencySnapshot,
}

impl EndpointSnapshot {
    fn since(&self, previous: &Self) -> Self {
        Self {
            requests: self.requests.saturating_sub(previous.requests),
            successful_responses: self
                .successful_responses
                .saturating_sub(previous.successful_responses),
            client_errors: self.client_errors.saturating_sub(previous.client_errors),
            server_errors: self.server_errors.saturating_sub(previous.server_errors),
            latency: self.latency.since(&previous.latency),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    pub(crate) requests: u64,
    pub(crate) successful_responses: u64,
    pub(crate) redirects: u64,
    pub(crate) client_errors: u64,
    pub(crate) server_errors: u64,
    pub(crate) job_requests: u64,
    pub(crate) cape_requests: u64,
    pub(crate) health_requests: u64,
    pub(crate) other_requests: u64,
    pub(crate) unattributed_requests: u64,
    pub(crate) mineskin_requests: u64,
    pub(crate) mineskin_errors: u64,
    pub(crate) mineskin_rate_limits: u64,
    pub(crate) bytes_received_from_mineskin: u64,
    pub(crate) request_latency: LatencySnapshot,
    pub(crate) mineskin_latency: LatencySnapshot,
    pub(crate) upload: EndpointSnapshot,
    pub(crate) decrypt: EndpointSnapshot,
    pub(crate) client_requests: HashMap<IpAddr, u64>,
    pub(crate) uptime: Duration,
    pub(crate) report_period: Duration,
}

impl MetricsSnapshot {
    #[must_use]
    pub fn since(&self, previous: &Self, report_period: Duration) -> Self {
        Self {
            requests: self.requests.saturating_sub(previous.requests),
            successful_responses: self
                .successful_responses
                .saturating_sub(previous.successful_responses),
            redirects: self.redirects.saturating_sub(previous.redirects),
            client_errors: self.client_errors.saturating_sub(previous.client_errors),
            server_errors: self.server_errors.saturating_sub(previous.server_errors),
            job_requests: self.job_requests.saturating_sub(previous.job_requests),
            cape_requests: self.cape_requests.saturating_sub(previous.cape_requests),
            health_requests: self
                .health_requests
                .saturating_sub(previous.health_requests),
            other_requests: self.other_requests.saturating_sub(previous.other_requests),
            unattributed_requests: self
                .unattributed_requests
                .saturating_sub(previous.unattributed_requests),
            mineskin_requests: self
                .mineskin_requests
                .saturating_sub(previous.mineskin_requests),
            mineskin_errors: self
                .mineskin_errors
                .saturating_sub(previous.mineskin_errors),
            mineskin_rate_limits: self
                .mineskin_rate_limits
                .saturating_sub(previous.mineskin_rate_limits),
            bytes_received_from_mineskin: self
                .bytes_received_from_mineskin
                .saturating_sub(previous.bytes_received_from_mineskin),
            request_latency: self.request_latency.since(&previous.request_latency),
            mineskin_latency: self.mineskin_latency.since(&previous.mineskin_latency),
            upload: self.upload.since(&previous.upload),
            decrypt: self.decrypt.since(&previous.decrypt),
            client_requests: self.client_requests.clone(),
            uptime: self.uptime,
            report_period,
        }
    }
}

#[derive(Debug, Default)]
struct EndpointMetrics {
    requests: AtomicU64,
    successful_responses: AtomicU64,
    client_errors: AtomicU64,
    server_errors: AtomicU64,
    latency: LatencyHistogram,
}

impl EndpointMetrics {
    fn record(&self, status: u16, latency: Duration) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.latency.record(latency);
        match status {
            200..=399 => {
                self.successful_responses.fetch_add(1, Ordering::Relaxed);
            }
            400..=499 => {
                self.client_errors.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.server_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn snapshot(&self) -> EndpointSnapshot {
        EndpointSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            successful_responses: self.successful_responses.load(Ordering::Relaxed),
            client_errors: self.client_errors.load(Ordering::Relaxed),
            server_errors: self.server_errors.load(Ordering::Relaxed),
            latency: self.latency.snapshot(),
        }
    }
}

#[derive(Debug)]
struct LatencyHistogram {
    buckets: [AtomicU64; LATENCY_BUCKET_UPPER_BOUNDS_MS.len()],
    total_micros: AtomicU64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            total_micros: AtomicU64::new(0),
        }
    }
}

impl LatencyHistogram {
    fn record(&self, latency: Duration) {
        let milliseconds = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
        let bucket = LATENCY_BUCKET_UPPER_BOUNDS_MS
            .iter()
            .position(|upper_bound| milliseconds <= *upper_bound)
            .unwrap_or(LATENCY_BUCKET_UPPER_BOUNDS_MS.len().saturating_sub(1));
        if let Some(counter) = self.buckets.get(bucket) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        self.total_micros.fetch_add(
            u64::try_from(latency.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn snapshot(&self) -> LatencySnapshot {
        LatencySnapshot {
            buckets: std::array::from_fn(|index| {
                self.buckets
                    .get(index)
                    .map_or(0, |counter| counter.load(Ordering::Relaxed))
            }),
            total_micros: self.total_micros.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr, time::Duration};

    use super::Metrics;

    #[test]
    fn keeps_concurrent_client_traffic_after_acknowledging_a_report() {
        let metrics = Metrics::default();
        let client = IpAddr::from_str("192.0.2.10").expect("test IP should be valid");
        metrics.record_request(
            "/mineskin/skins",
            200,
            Some(client),
            Duration::from_millis(20),
        );
        let baseline = Metrics::default().snapshot();
        let reported = metrics.snapshot();

        metrics.record_request(
            "/mineskin/jobs/1",
            502,
            Some(client),
            Duration::from_millis(600),
        );
        metrics.record_request(
            "/mineskin/decrypt-url",
            400,
            Some(client),
            Duration::from_millis(70),
        );
        metrics.acknowledge_client_requests(&reported);

        let current = metrics.snapshot();
        let window = current.since(&baseline, Duration::from_mins(5));
        assert_eq!(current.client_requests.get(&client), Some(&2));
        assert_eq!(window.requests, 3);
        assert_eq!(window.upload.requests, 1);
        assert_eq!(window.upload.successful_responses, 1);
        assert_eq!(window.decrypt.requests, 1);
        assert_eq!(window.decrypt.client_errors, 1);
        assert_eq!(window.job_requests, 1);
        assert_eq!(window.server_errors, 1);
        assert_eq!(window.client_errors, 1);
        assert_eq!(
            window.upload.latency.percentile(95),
            Duration::from_millis(25)
        );
        assert_eq!(
            window.request_latency.percentile(95),
            Duration::from_secs(1)
        );
    }
}
