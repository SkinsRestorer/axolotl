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
    statuses: StatusCounters,
    other_requests: AtomicU64,
    unattributed_requests: AtomicU64,
    mineskin_requests: AtomicU64,
    mineskin_errors: AtomicU64,
    mineskin_rate_limits: AtomicU64,
    mineskin_latency: LatencyHistogram,
    upload: EndpointMetrics,
    decrypt: EndpointMetrics,
    track_clients: bool,
    client_requests: Mutex<HashMap<IpAddr, u64>>,
    started_at: Instant,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            requests: AtomicU64::new(0),
            statuses: StatusCounters::default(),
            other_requests: AtomicU64::new(0),
            unattributed_requests: AtomicU64::new(0),
            mineskin_requests: AtomicU64::new(0),
            mineskin_errors: AtomicU64::new(0),
            mineskin_rate_limits: AtomicU64::new(0),
            mineskin_latency: LatencyHistogram::default(),
            upload: EndpointMetrics::default(),
            decrypt: EndpointMetrics::default(),
            track_clients: true,
            client_requests: Mutex::new(HashMap::new()),
            started_at: Instant::now(),
        }
    }
}

impl Metrics {
    /// Creates metrics that do not record client IPs.
    ///
    /// Only the Discord report reads the per-IP table, and nothing empties it
    /// without a report. Use this when reports are disabled so the table does
    /// not grow to its cap and stay there.
    #[must_use]
    pub fn without_client_tracking() -> Self {
        Self {
            track_clients: false,
            ..Self::default()
        }
    }

    pub fn record_request(
        &self,
        path: &str,
        status: u16,
        client_ip: Option<IpAddr>,
        latency: Duration,
    ) {
        if !self.track_clients {
            self.record_counters(path, status, latency);
            return;
        }

        // Snapshots must observe request totals and client attribution under
        // the same lock.
        let mut client_requests = self.lock_client_requests();
        self.record_counters(path, status, latency);
        if !client_ip.is_some_and(|client_ip| record_client(&mut client_requests, client_ip)) {
            self.unattributed_requests.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn finish_mineskin_request(&self, latency: Duration, failed: bool, rate_limited: bool) {
        // Hold the snapshot lock so that a snapshot never counts this call's
        // error or rate limit without also counting the call itself.
        let snapshot_lock = self.lock_client_requests();
        self.mineskin_requests.fetch_add(1, Ordering::Relaxed);
        self.mineskin_latency.record(latency);
        if failed {
            self.mineskin_errors.fetch_add(1, Ordering::Relaxed);
        }
        if rate_limited {
            self.mineskin_rate_limits.fetch_add(1, Ordering::Relaxed);
        }
        drop(snapshot_lock);
    }

    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        let client_requests = self.lock_client_requests();
        MetricsSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            client_errors: self.statuses.client_errors.load(Ordering::Relaxed),
            server_errors: self.statuses.server_errors.load(Ordering::Relaxed),
            other_requests: self.other_requests.load(Ordering::Relaxed),
            unattributed_requests: self.unattributed_requests.load(Ordering::Relaxed),
            mineskin_requests: self.mineskin_requests.load(Ordering::Relaxed),
            mineskin_errors: self.mineskin_errors.load(Ordering::Relaxed),
            mineskin_rate_limits: self.mineskin_rate_limits.load(Ordering::Relaxed),
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
        acknowledge_clients(&mut requests, &snapshot.client_requests);
    }

    fn lock_client_requests(&self) -> MutexGuard<'_, HashMap<IpAddr, u64>> {
        self.client_requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn record_counters(&self, path: &str, status: u16, latency: Duration) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.statuses.record(status);
        match path {
            "/mineskin/skins" => self.upload.record(status, latency),
            "/mineskin/decrypt-url" => self.decrypt.record(status, latency),
            _ => {
                self.other_requests.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn record_client(requests: &mut HashMap<IpAddr, u64>, client_ip: IpAddr) -> bool {
    if let Some(count) = requests.get_mut(&client_ip) {
        *count = count.saturating_add(1);
        return true;
    }
    if requests.len() >= MAX_TRACKED_CLIENTS {
        return false;
    }

    requests.insert(client_ip, 1);
    true
}

fn acknowledge_clients(
    requests: &mut HashMap<IpAddr, u64>,
    acknowledged_requests: &HashMap<IpAddr, u64>,
) {
    #[expect(
        clippy::iter_over_hash_type,
        reason = "acknowledgement subtracts each client's count independently"
    )]
    for (client_ip, acknowledged) in acknowledged_requests {
        if let Some(current) = requests.get_mut(client_ip) {
            *current = current.saturating_sub(*acknowledged);
        }
    }
    requests.retain(|_, count| *count > 0);
    // `retain` keeps the allocation, and cloning a map copies its full
    // capacity. Without this, one burst of clients would make every later
    // snapshot copy megabytes of empty buckets.
    requests.shrink_to_fit();
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LatencySnapshot {
    buckets: [u64; LATENCY_BUCKET_UPPER_BOUNDS_MS.len()],
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
        }
    }

    #[must_use]
    pub(crate) fn count(&self) -> u64 {
        self.buckets
            .iter()
            .fold(0_u64, |count, bucket| count.saturating_add(*bucket))
    }

    /// Returns the upper bound of the bucket that holds the percentile, or
    /// zero when nothing was recorded. The open-ended last bucket reports
    /// 60.001 s.
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
    pub(crate) client_errors: u64,
    pub(crate) server_errors: u64,
    pub(crate) latency: LatencySnapshot,
}

impl EndpointSnapshot {
    fn since(&self, previous: &Self) -> Self {
        Self {
            requests: self.requests.saturating_sub(previous.requests),
            client_errors: self.client_errors.saturating_sub(previous.client_errors),
            server_errors: self.server_errors.saturating_sub(previous.server_errors),
            latency: self.latency.since(&previous.latency),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    pub(crate) requests: u64,
    pub(crate) client_errors: u64,
    pub(crate) server_errors: u64,
    /// Requests that were neither uploads nor decryptions.
    pub(crate) other_requests: u64,
    pub(crate) unattributed_requests: u64,
    pub(crate) mineskin_requests: u64,
    /// Failed `MineSkin` calls, including rate-limited ones.
    pub(crate) mineskin_errors: u64,
    pub(crate) mineskin_rate_limits: u64,
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
            client_errors: self.client_errors.saturating_sub(previous.client_errors),
            server_errors: self.server_errors.saturating_sub(previous.server_errors),
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
    statuses: StatusCounters,
    latency: LatencyHistogram,
}

impl EndpointMetrics {
    fn record(&self, status: u16, latency: Duration) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.latency.record(latency);
        self.statuses.record(status);
    }

    fn snapshot(&self) -> EndpointSnapshot {
        EndpointSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            client_errors: self.statuses.client_errors.load(Ordering::Relaxed),
            server_errors: self.statuses.server_errors.load(Ordering::Relaxed),
            latency: self.latency.snapshot(),
        }
    }
}

/// Counts error responses by status class. The global counters and the
/// per-endpoint counters share it so their sections in a report agree.
#[derive(Debug, Default)]
struct StatusCounters {
    client_errors: AtomicU64,
    server_errors: AtomicU64,
}

impl StatusCounters {
    fn record(&self, status: u16) {
        let counter = match status {
            // Informational, successful and redirect responses did not fail.
            100..=399 => return,
            400..=499 => &self.client_errors,
            _ => &self.server_errors,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct LatencyHistogram {
    buckets: [AtomicU64; LATENCY_BUCKET_UPPER_BOUNDS_MS.len()],
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl LatencyHistogram {
    fn record(&self, latency: Duration) {
        // Compare the full duration so that, for example, 60.5 s lands in the
        // >60 s bucket instead of being truncated into the 60 s bucket.
        let bucket = LATENCY_BUCKET_UPPER_BOUNDS_MS
            .iter()
            .position(|upper_bound| latency <= Duration::from_millis(*upper_bound))
            .unwrap_or(LATENCY_BUCKET_UPPER_BOUNDS_MS.len().saturating_sub(1));
        if let Some(counter) = self.buckets.get(bucket) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> LatencySnapshot {
        LatencySnapshot {
            buckets: std::array::from_fn(|index| {
                self.buckets
                    .get(index)
                    .map_or(0, |counter| counter.load(Ordering::Relaxed))
            }),
        }
    }
}
#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr, sync::Arc, thread, time::Duration};

    use super::{LATENCY_BUCKET_UPPER_BOUNDS_MS, LatencySnapshot, Metrics};

    #[test]
    fn saturates_the_latency_count_instead_of_overflowing() {
        let latency = LatencySnapshot {
            buckets: [u64::MAX; LATENCY_BUCKET_UPPER_BOUNDS_MS.len()],
        };
        assert_eq!(latency.count(), u64::MAX);
    }

    #[test]
    fn never_snapshots_more_mineskin_errors_than_mineskin_calls() {
        let metrics = Arc::new(Metrics::default());
        let writers: Vec<_> = (0..4)
            .map(|_| {
                let metrics = Arc::clone(&metrics);
                thread::spawn(move || {
                    for _ in 0..20_000 {
                        metrics.finish_mineskin_request(Duration::from_millis(1), true, true);
                    }
                })
            })
            .collect();

        for _ in 0..20_000 {
            let snapshot = metrics.snapshot();
            assert!(snapshot.mineskin_errors <= snapshot.mineskin_requests);
            assert!(snapshot.mineskin_rate_limits <= snapshot.mineskin_requests);
            assert_eq!(
                snapshot.mineskin_latency.count(),
                snapshot.mineskin_requests
            );
        }
        for writer in writers {
            writer.join().expect("writer thread should not panic");
        }
    }

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
            None,
            Duration::from_millis(70),
        );
        let window = metrics.snapshot().since(&baseline, Duration::from_mins(5));
        assert_eq!(window.requests, 3);
        assert_eq!(window.upload.requests, 1);
        assert_eq!(window.upload.server_errors, 0);
        assert_eq!(window.decrypt.requests, 1);
        assert_eq!(window.decrypt.client_errors, 1);
        assert_eq!(window.other_requests, 1);
        assert_eq!(window.server_errors, 1);
        assert_eq!(window.client_errors, 1);
        assert_eq!(window.unattributed_requests, 1);
        assert_eq!(window.client_requests.get(&client), Some(&2));
        assert_eq!(
            window.upload.latency.percentile(95),
            Duration::from_millis(25)
        );

        metrics.acknowledge_client_requests(&reported);
        let after_acknowledgement = metrics.snapshot();
        assert_eq!(after_acknowledgement.client_requests.get(&client), Some(&1));
    }

    #[test]
    fn skips_client_tables_without_client_tracking() {
        let metrics = Metrics::without_client_tracking();
        let client = IpAddr::from_str("192.0.2.10").expect("test IP should be valid");
        metrics.record_request(
            "/mineskin/skins",
            503,
            Some(client),
            Duration::from_millis(20),
        );

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.requests, 1);
        assert_eq!(snapshot.upload.server_errors, 1);
        assert!(snapshot.client_requests.is_empty());
        assert_eq!(snapshot.unattributed_requests, 0);
    }

    #[test]
    fn releases_client_table_memory_after_acknowledging_a_burst() {
        let metrics = Metrics::default();
        for index in 0_u32..10_000 {
            metrics.record_request(
                "/mineskin/skins",
                200,
                Some(IpAddr::from(index.to_be_bytes())),
                Duration::from_millis(5),
            );
        }
        let reported = metrics.snapshot();
        metrics.acknowledge_client_requests(&reported);

        let client = IpAddr::from_str("192.0.2.10").expect("test IP should be valid");
        metrics.record_request(
            "/mineskin/skins",
            200,
            Some(client),
            Duration::from_millis(5),
        );
        let next = metrics.snapshot();
        assert_eq!(next.client_requests.len(), 1);
        assert!(next.client_requests.capacity() < 100);
    }

    #[test]
    fn counts_a_mineskin_call_in_the_window_where_it_finishes() {
        let metrics = Metrics::default();
        let baseline = metrics.snapshot();
        let first_report = metrics.snapshot();
        let first_window = first_report.since(&baseline, Duration::from_mins(5));
        assert_eq!(first_window.mineskin_requests, 0);
        assert_eq!(first_window.mineskin_errors, 0);

        metrics.finish_mineskin_request(Duration::from_secs(2), true, true);
        metrics.finish_mineskin_request(Duration::from_secs(3), true, false);
        let second_window = metrics
            .snapshot()
            .since(&first_report, Duration::from_mins(5));
        assert_eq!(second_window.mineskin_requests, 2);
        assert_eq!(second_window.mineskin_errors, 2);
        assert_eq!(second_window.mineskin_rate_limits, 1);
        assert_eq!(second_window.mineskin_latency.count(), 2);
    }

    #[test]
    fn classifies_endpoint_statuses_like_global_traffic() {
        let metrics = Metrics::default();
        for status in [101, 200, 302, 404, 503] {
            metrics.record_request("/mineskin/skins", status, None, Duration::from_millis(5));
        }

        let window = metrics
            .snapshot()
            .since(&Metrics::default().snapshot(), Duration::from_mins(5));
        assert_eq!(window.client_errors, 1);
        assert_eq!(window.server_errors, 1);
        assert_eq!(window.upload.requests, 5);
        assert_eq!(window.upload.client_errors, window.client_errors);
        assert_eq!(window.upload.server_errors, window.server_errors);
    }

    #[test]
    fn puts_latencies_just_above_a_bucket_edge_in_the_next_bucket() {
        let metrics = Metrics::default();
        metrics.finish_mineskin_request(Duration::from_millis(5), false, false);
        let snapshot = metrics.snapshot();
        assert_eq!(
            snapshot.mineskin_latency.percentile(95),
            Duration::from_millis(5)
        );

        let metrics = Metrics::default();
        metrics.finish_mineskin_request(Duration::from_micros(5_400), false, false);
        assert_eq!(
            metrics.snapshot().mineskin_latency.percentile(95),
            Duration::from_millis(10)
        );

        let metrics = Metrics::default();
        metrics.finish_mineskin_request(Duration::from_micros(60_000_500), false, false);
        assert_eq!(
            metrics.snapshot().mineskin_latency.percentile(50),
            Duration::from_millis(60_001)
        );
    }
}
