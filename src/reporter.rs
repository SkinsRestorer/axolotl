#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use reqwest::Url;
use serde_json::json;
use tokio::{
    fs,
    sync::oneshot,
    task::JoinHandle,
    time::{MissedTickBehavior, interval},
};
use tracing::{error, info};

use crate::{
    http_client,
    metrics::{EndpointSnapshot, LatencySnapshot, Metrics, MetricsSnapshot},
};

const REPORT_INTERVAL: Duration = Duration::from_mins(5);

pub struct DiscordReporter {
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl DiscordReporter {
    #[must_use]
    pub fn start(webhook: Option<Url>, metrics: Arc<Metrics>) -> Self {
        let Some(webhook) = webhook else {
            info!("DISCORD_WEBHOOK is not set; status reports are disabled");
            return Self {
                shutdown: None,
                task: None,
            };
        };

        let (shutdown, shutdown_receiver) = oneshot::channel();
        let initial_snapshot = metrics.snapshot();
        let reporter_started_at = Instant::now();
        let task = tokio::spawn(async move {
            let client = match http_client::builder(Duration::from_secs(15))
                .https_only(true)
                .build()
            {
                Ok(client) => client,
                Err(error) => {
                    error!(%error, "Could not create Discord HTTP client");
                    return;
                }
            };
            run(
                &client,
                &webhook,
                &metrics,
                shutdown_receiver,
                initial_snapshot,
                reporter_started_at,
                REPORT_INTERVAL,
            )
            .await;
        });
        info!("Discord status reporter started");
        Self {
            shutdown: Some(shutdown),
            task: Some(task),
        }
    }

    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "the reporter may already have stopped and dropped the shutdown receiver"
            )]
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take()
            && let Err(error) = task.await
        {
            error!(%error, "Discord status reporter stopped unexpectedly");
        }
    }
}

async fn run(
    client: &reqwest::Client,
    webhook: &Url,
    metrics: &Metrics,
    mut shutdown_receiver: oneshot::Receiver<()>,
    initial_snapshot: MetricsSnapshot,
    reporter_started_at: Instant,
    report_interval: Duration,
) {
    let mut ticker = interval(report_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker.tick().await;
    let mut last_successful_snapshot = initial_snapshot;
    let mut last_successful_report_at = reporter_started_at;

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown_receiver => break,
            _ = ticker.tick() => {}
        }
        let now = Instant::now();
        let current_snapshot = metrics.snapshot();
        let report = current_snapshot.since(
            &last_successful_snapshot,
            now.saturating_duration_since(last_successful_report_at),
        );
        // A slow webhook must not hold up shutdown until the request times out.
        let result = tokio::select! {
            biased;
            _ = &mut shutdown_receiver => break,
            result = send_report(client, webhook, &report) => result,
        };
        match result {
            Ok(()) => {
                metrics.acknowledge_client_requests(&current_snapshot);
                last_successful_snapshot = current_snapshot;
                // The next report reads only the counters from this snapshot,
                // so don't keep another copy of the client table.
                last_successful_snapshot.client_requests = HashMap::new();
                last_successful_report_at = now;
            }
            Err(error) => {
                error!(%error, "Failed to send Discord status report");
            }
        }
    }
}

async fn send_report(
    client: &reqwest::Client,
    webhook: &Url,
    snapshot: &MetricsSnapshot,
) -> Result<(), reqwest::Error> {
    let host = HostStats {
        rss_bytes: process_rss_bytes().await,
        load_average: load_average().await,
    };
    // The webhook URL contains its secret token, so keep it out of logged errors.
    client
        .post(webhook.clone())
        .json(&build_report(snapshot, &host))
        .send()
        .await
        .map_err(reqwest::Error::without_url)?
        .error_for_status()
        .map_err(reqwest::Error::without_url)?;
    Ok(())
}

struct HostStats {
    rss_bytes: Option<u64>,
    load_average: Option<String>,
}

fn build_report(snapshot: &MetricsSnapshot, host: &HostStats) -> serde_json::Value {
    let status = Status::of(snapshot);
    json!({
        "embeds": [{
            "title": format!("Axolotl: {}", status.label()),
            "color": status.color(),
            "description": headline(snapshot),
            "fields": [
                {
                    "name": "Uploads",
                    "value": endpoint_stats(&snapshot.upload),
                    "inline": true
                },
                {
                    "name": "Decryptions",
                    "value": endpoint_stats(&snapshot.decrypt),
                    "inline": true
                },
                {
                    "name": "MineSkin",
                    "value": mineskin_stats(snapshot),
                    "inline": true
                },
                {
                    "name": "Clients",
                    "value": client_stats(snapshot),
                    "inline": false
                }
            ],
            // Discord documents only "ISO8601", so send millisecond precision like
            // JavaScript's `toISOString` instead of jiff's default nanoseconds.
            "timestamp": format!("{:.3}", jiff::Timestamp::now()),
            "footer": { "text": footer(snapshot, host) }
        }]
    })
}

/// Overall health of one report window.
///
/// Rates, not counts, decide the status, so a busy window with a few stray
/// errors stays healthy. A rate only counts once at least
/// [`MIN_ERRORS_FOR_STATUS`] errors back it, so one failure in a quiet window
/// does not mark the service as failing. The headline still shows every error.
///
/// | Signal                                          | Degraded | Failing |
/// |-------------------------------------------------|----------|---------|
/// | 5xx responses / all requests                    | ≥ 1%     | ≥ 5%    |
/// | Failed `MineSkin` calls / `MineSkin` calls      | ≥ 10%    | ≥ 50%   |
/// | Rate-limited `MineSkin` calls / `MineSkin` calls | ≥ 5%     |         |
///
/// Failed `MineSkin` calls include rate-limited ones, so heavy rate limiting
/// also reaches Failing through the error rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Status {
    Healthy,
    Degraded,
    Failing,
}

const MIN_ERRORS_FOR_STATUS: u64 = 3;

impl Status {
    fn of(snapshot: &MetricsSnapshot) -> Self {
        let server_errors = Self::from_rate(
            snapshot.server_errors,
            snapshot.requests,
            Some(1.0),
            Some(5.0),
        );
        let mineskin_errors = Self::from_rate(
            snapshot.mineskin_errors,
            snapshot.mineskin_requests,
            Some(10.0),
            Some(50.0),
        );
        let rate_limits = Self::from_rate(
            snapshot.mineskin_rate_limits,
            snapshot.mineskin_requests,
            Some(5.0),
            None,
        );
        server_errors.max(mineskin_errors).max(rate_limits)
    }

    fn from_rate(
        errors: u64,
        total: u64,
        degraded_percent: Option<f64>,
        failing_percent: Option<f64>,
    ) -> Self {
        if errors < MIN_ERRORS_FOR_STATUS {
            return Self::Healthy;
        }
        let rate = percentage(errors, total);
        if failing_percent.is_some_and(|threshold| rate >= threshold) {
            Self::Failing
        } else if degraded_percent.is_some_and(|threshold| rate >= threshold) {
            Self::Degraded
        } else {
            Self::Healthy
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Healthy => "Healthy",
            Self::Degraded => "Degraded",
            Self::Failing => "Failing",
        }
    }

    const fn color(self) -> u32 {
        match self {
            Self::Healthy => 0x002e_cc71,
            Self::Degraded => 0x00f3_9c12,
            Self::Failing => 0x00e7_4c3c,
        }
    }
}

fn headline(snapshot: &MetricsSnapshot) -> String {
    let period = format_report_period(snapshot.report_period);
    if snapshot.requests == 0 && snapshot.mineskin_requests == 0 {
        return format!("No requests in {period}");
    }

    let mut parts = Vec::new();
    if snapshot.server_errors > 0 {
        parts.push(format!(
            "{} ({:.1}%)",
            plural(snapshot.server_errors, "server error", "server errors"),
            percentage(snapshot.server_errors, snapshot.requests)
        ));
    }
    let errors = snapshot.mineskin_errors;
    let rate_limits = snapshot.mineskin_rate_limits;
    if errors > rate_limits {
        let part = plural(errors, "MineSkin error", "MineSkin errors");
        parts.push(if rate_limits > 0 {
            format!(
                "{part} ({})",
                plural(rate_limits, "rate limit", "rate limits")
            )
        } else {
            part
        });
    } else if rate_limits > 0 {
        parts.push(plural(
            rate_limits,
            "MineSkin rate limit",
            "MineSkin rate limits",
        ));
    }
    if parts.is_empty() {
        parts.push("No errors".to_owned());
    }
    parts.push(format!(
        "{} in {period}",
        plural(snapshot.requests, "request", "requests")
    ));
    parts.join(" · ")
}

fn endpoint_stats(snapshot: &EndpointSnapshot) -> String {
    if snapshot.requests == 0 {
        return "No requests".to_owned();
    }
    format!(
        "{}\n5xx: {} · 4xx: {}\n{}",
        plural(snapshot.requests, "request", "requests"),
        format_number(snapshot.server_errors),
        format_number(snapshot.client_errors),
        p95(&snapshot.latency)
    )
}

fn mineskin_stats(snapshot: &MetricsSnapshot) -> String {
    if snapshot.mineskin_requests == 0 {
        return "No calls".to_owned();
    }
    format!(
        "{}\nErrors: {} · Rate limits: {}\n{}",
        plural(snapshot.mineskin_requests, "call", "calls"),
        format_number(snapshot.mineskin_errors),
        format_number(snapshot.mineskin_rate_limits),
        p95(&snapshot.mineskin_latency)
    )
}

fn client_stats(snapshot: &MetricsSnapshot) -> String {
    let unique_clients = u64::try_from(snapshot.client_requests.len()).unwrap_or(u64::MAX);
    let attributed_requests = snapshot.client_requests.values().sum::<u64>();
    let top_client_requests = snapshot
        .client_requests
        .values()
        .copied()
        .max()
        .unwrap_or_default();

    let mut lines = Vec::new();
    if unique_clients == 0 {
        lines.push("No client IPs".to_owned());
    } else {
        lines.push(plural(unique_clients, "unique IP", "unique IPs"));
        lines.push(format!(
            "Top IP: {:.1}% of requests",
            percentage(top_client_requests, attributed_requests)
        ));
    }
    if snapshot.unattributed_requests > 0 {
        lines.push(format!(
            "Unattributed: {}",
            plural(snapshot.unattributed_requests, "request", "requests")
        ));
    }
    lines.join("\n")
}

fn footer(snapshot: &MetricsSnapshot, host: &HostStats) -> String {
    let rss = host
        .rss_bytes
        .map_or_else(|| "unavailable".to_owned(), format_bytes);
    let load_average = host.load_average.as_deref().unwrap_or("unavailable");
    format!(
        "Axolotl v{} · up {} · RSS {rss} · load {load_average}",
        env!("CARGO_PKG_VERSION"),
        format_duration(snapshot.uptime)
    )
}

fn plural(count: u64, singular: &str, plural: &str) -> String {
    let noun = if count == 1 { singular } else { plural };
    format!("{} {noun}", format_number(count))
}

/// Percentiles come from histogram buckets and report the bucket's upper
/// bound, so a value only means "at most this long". The last bucket has no
/// upper bound, so anything above its 60 s lower bound means "more than 60 s".
fn p95(latency: &LatencySnapshot) -> String {
    let duration = latency.percentile(95);
    if duration.is_zero() {
        return "p95 N/A".to_owned();
    }
    if duration > Duration::from_mins(1) {
        return "p95 > 60 s".to_owned();
    }
    // Bucket bounds are whole milliseconds of at least 5 ms.
    if duration < Duration::from_secs(1) {
        format!("p95 ≤ {} ms", duration.as_millis())
    } else {
        format!("p95 ≤ {} s", duration.as_secs_f64())
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "the reported metric is rounded for display"
)]
fn percentage(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 / total as f64 * 100.0
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "the reported metric is rounded for display"
)]
fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let kibibytes = format!("{:.2}", bytes as f64 / KIB);
    // Sizes just under 1 MiB round up to "1024.00", so show those in MiB.
    if kibibytes == "1024.00" || bytes >= 1_048_576 {
        format!("{:.2} MiB", bytes as f64 / MIB)
    } else {
        format!("{kibibytes} KiB")
    }
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let days = seconds / 86_400;
    let hours = seconds % 86_400 / 3_600;
    let minutes = seconds % 3_600 / 60;
    let seconds = seconds % 60;
    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    parts.push(format!("{seconds}s"));
    parts.join(" ")
}

fn format_report_period(duration: Duration) -> String {
    // Ticks fire slightly after the interval, so round to the nearest minute
    // instead of up, and never label a short window as "0min".
    let minutes = (duration.as_secs().saturating_add(30) / 60).max(1);
    format!("{minutes} min")
}

fn format_number(number: u64) -> String {
    let digits = number.to_string();
    let mut formatted = String::with_capacity(digits.len().saturating_add(digits.len() / 3));
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && digits.len().saturating_sub(index).is_multiple_of(3) {
            formatted.push(',');
        }
        formatted.push(character);
    }
    formatted
}

async fn process_rss_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").await.ok()?;
    let kibibytes = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;
    kibibytes.checked_mul(1024)
}

async fn load_average() -> Option<String> {
    let load_average = fs::read_to_string("/proc/loadavg").await.ok()?;
    let values = load_average.split_whitespace().take(3).collect::<Vec<_>>();
    (values.len() == 3).then(|| values.join(" / "))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
        time::{Duration, Instant},
    };

    use serde_json::Value;
    use tokio::{sync::oneshot, time::timeout};
    use url::Url;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

    use super::{
        HostStats, Metrics, MetricsSnapshot, Status, build_report, format_bytes,
        format_report_period, p95, run, send_report,
    };

    const fn no_host_stats() -> HostStats {
        HostStats {
            rss_bytes: None,
            load_average: None,
        }
    }

    fn text(value: &Value, pointer: &str) -> String {
        value
            .pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }

    /// Returns the title, the description, each field and the footer as
    /// (name, text) pairs, in display order.
    fn embed_text(report: &Value) -> Vec<(String, String)> {
        let mut parts = vec![
            ("title".to_owned(), text(report, "/embeds/0/title")),
            (
                "description".to_owned(),
                text(report, "/embeds/0/description"),
            ),
        ];
        let fields = report
            .pointer("/embeds/0/fields")
            .and_then(Value::as_array)
            .expect("the embed should have fields");
        for field in fields {
            parts.push((text(field, "/name"), text(field, "/value")));
        }
        parts.push(("footer".to_owned(), text(report, "/embeds/0/footer/text")));
        parts
    }

    fn assert_within_discord_limits(report: &Value) {
        let parts = embed_text(report);
        let length = |index: usize| parts.get(index).map_or(0, |(_, text)| text.chars().count());
        assert!(length(0) <= 256);
        assert!(length(1) <= 4096);
        assert!(length(parts.len().saturating_sub(1)) <= 2048);
        let fields = parts
            .get(2..parts.len().saturating_sub(1))
            .unwrap_or_default();
        assert!(fields.len() <= 25);
        for (name, value) in fields {
            assert!(name.chars().count() <= 256);
            assert!(value.chars().count() <= 1024);
            assert!(!value.is_empty(), "Discord rejects empty field {name}");
        }
        let total = fields
            .iter()
            .map(|(name, _)| name.chars().count())
            .chain(parts.iter().map(|(_, text)| text.chars().count()))
            .sum::<usize>();
        assert!(total <= 6000, "embed has {total} characters");
    }

    /// Records a busy five-minute window: 2,455 requests from 312 IPs.
    fn busy_window() -> MetricsSnapshot {
        let metrics = Metrics::default();
        let top_client = IpAddr::from([198, 51, 100, 1]);
        let client_ip = |index: u32| match index {
            0..3 => None,
            3..155 => Some(top_client),
            // Spread the rest over 311 more IPs in 10.0.0.0/8.
            _ => Some(IpAddr::V4(Ipv4Addr::from(
                0x0a00_0000_u32.saturating_add(index.saturating_sub(155) % 311),
            ))),
        };
        let mut index = 0;
        let mut record = |path: &str, status: u16, latency: Duration| {
            metrics.record_request(path, status, client_ip(index), latency);
            index = index.saturating_add(1);
        };
        for upload in 0..1_820 {
            let status = match upload {
                0..6 => 503,
                6..47 => 400,
                _ => 200,
            };
            let latency = if upload < 120 { 2_000 } else { 800 };
            record("/mineskin/skins", status, Duration::from_millis(latency));
        }
        for decryption in 0..610 {
            let status = if decryption < 3 { 400 } else { 200 };
            record("/mineskin/decrypt-url", status, Duration::from_millis(2));
        }
        for _ in 0..25 {
            record("/mineskin/jobs/abc", 200, Duration::from_millis(40));
        }
        for call in 0..1_912 {
            let latency = if call < 62 { 4_000 } else { 1_200 };
            metrics.finish_mineskin_request(Duration::from_millis(latency), call < 4, call < 2);
        }

        let mut window = metrics
            .snapshot()
            .since(&MetricsSnapshot::default(), Duration::from_secs(301));
        window.uptime = Duration::from_secs(3 * 86_400 + 4 * 3_600 + 12 * 60 + 5);
        window
    }

    #[test]
    fn renders_a_busy_window() {
        let report = build_report(
            &busy_window(),
            &HostStats {
                rss_bytes: Some(48 * 1024 * 1024 + 300 * 1024),
                load_average: Some("0.42 / 0.37 / 0.30".to_owned()),
            },
        );
        let rendered = embed_text(&report)
            .into_iter()
            .map(|(name, value)| format!("[{name}]\n{value}"))
            .collect::<Vec<_>>()
            .join("\n\n");
        println!("{rendered}");

        let version = env!("CARGO_PKG_VERSION");
        assert_eq!(
            rendered,
            format!(
                "[title]\nAxolotl: Healthy\n\n\
                 [description]\n6 server errors (0.2%) · 4 MineSkin errors (2 rate limits) · 2,455 requests in 5 min\n\n\
                 [Uploads]\n1,820 requests\n5xx: 6 · 4xx: 41\np95 ≤ 2.5 s\n\n\
                 [Decryptions]\n610 requests\n5xx: 0 · 4xx: 3\np95 ≤ 5 ms\n\n\
                 [MineSkin]\n1,912 calls\nErrors: 4 · Rate limits: 2\np95 ≤ 2.5 s\n\n\
                 [Clients]\n312 unique IPs\nTop IP: 6.2% of requests\nUnattributed: 3 requests\n\n\
                 [footer]\nAxolotl v{version} · up 3d 4h 12m 5s · RSS 48.29 MiB · load 0.42 / 0.37 / 0.30"
            )
        );
        assert_eq!(
            report.pointer("/embeds/0/color").and_then(Value::as_u64),
            Some(0x002e_cc71)
        );
        assert_within_discord_limits(&report);
    }

    #[test]
    fn renders_an_idle_window_without_empty_fields() {
        let report = build_report(&MetricsSnapshot::default(), &no_host_stats());
        let text = embed_text(&report);
        let value = |name: &str| {
            text.iter()
                .find(|(field, _)| field == name)
                .map(|(_, value)| value.as_str())
                .expect("the part should exist")
        };

        assert_eq!(value("title"), "Axolotl: Healthy");
        assert_eq!(value("description"), "No requests in 1 min");
        assert_eq!(value("Uploads"), "No requests");
        assert_eq!(value("Decryptions"), "No requests");
        assert_eq!(value("MineSkin"), "No calls");
        assert_eq!(value("Clients"), "No client IPs");
        assert!(value("footer").ends_with("RSS unavailable · load unavailable"));
        assert_within_discord_limits(&report);
    }

    #[test]
    fn stays_within_discord_limits_with_extreme_counts() {
        let snapshot = MetricsSnapshot {
            requests: u64::MAX,
            client_errors: u64::MAX,
            server_errors: u64::MAX,
            unattributed_requests: u64::MAX,
            mineskin_requests: u64::MAX,
            mineskin_errors: u64::MAX,
            mineskin_rate_limits: u64::MAX - 1,
            uptime: Duration::MAX,
            report_period: Duration::MAX,
            ..MetricsSnapshot::default()
        };
        let report = build_report(
            &snapshot,
            &HostStats {
                rss_bytes: Some(u64::MAX),
                load_average: Some("999.99 / 999.99 / 999.99".to_owned()),
            },
        );

        assert_eq!(text(&report, "/embeds/0/title"), "Axolotl: Failing");
        assert_within_discord_limits(&report);
    }

    #[test]
    fn mentions_only_the_problems_that_occurred() {
        let headline = |snapshot: MetricsSnapshot| {
            text(
                &build_report(&snapshot, &no_host_stats()),
                "/embeds/0/description",
            )
        };
        let window = |requests, server_errors, mineskin_errors, rate_limits| MetricsSnapshot {
            requests,
            server_errors,
            mineskin_requests: 100,
            mineskin_errors,
            mineskin_rate_limits: rate_limits,
            report_period: Duration::from_mins(5),
            ..MetricsSnapshot::default()
        };

        assert_eq!(
            headline(window(1, 0, 0, 0)),
            "No errors · 1 request in 5 min"
        );
        assert_eq!(
            headline(window(2_455, 6, 2, 2)),
            "6 server errors (0.2%) · 2 MineSkin rate limits · 2,455 requests in 5 min"
        );
        assert_eq!(
            headline(window(10, 1, 1, 0)),
            "1 server error (10.0%) · 1 MineSkin error · 10 requests in 5 min"
        );
    }

    #[test]
    fn derives_the_status_from_error_rates() {
        let status = |requests, server_errors, mineskin_requests, mineskin_errors, rate_limits| {
            Status::of(&MetricsSnapshot {
                requests,
                server_errors,
                mineskin_requests,
                mineskin_errors,
                mineskin_rate_limits: rate_limits,
                ..MetricsSnapshot::default()
            })
        };

        assert_eq!(status(10_000, 50, 0, 0, 0), Status::Healthy);
        assert_eq!(status(100, 3, 0, 0, 0), Status::Degraded);
        assert_eq!(status(100, 5, 0, 0, 0), Status::Failing);
        // Too few errors to judge a rate, however high it is.
        assert_eq!(status(2, 2, 2, 2, 2), Status::Healthy);
        assert_eq!(status(0, 0, 100, 9, 0), Status::Healthy);
        assert_eq!(status(0, 0, 100, 10, 0), Status::Degraded);
        assert_eq!(status(0, 0, 100, 50, 0), Status::Failing);
        assert_eq!(status(0, 0, 100, 5, 5), Status::Degraded);
        assert_eq!(status(0, 0, 100, 60, 60), Status::Failing);
    }

    #[test]
    fn shows_p95_as_a_bucket_upper_bound() {
        let p95_of = |latency| {
            let metrics = Metrics::default();
            metrics.finish_mineskin_request(latency, false, false);
            p95(&metrics.snapshot().mineskin_latency)
        };

        // The call took 0.4 ms, so the 5 ms bucket bound is not the p95 itself.
        assert_eq!(p95_of(Duration::from_micros(400)), "p95 ≤ 5 ms");
        assert_eq!(p95_of(Duration::from_millis(250)), "p95 ≤ 250 ms");
        assert_eq!(p95_of(Duration::from_millis(1_200)), "p95 ≤ 2.5 s");
        assert_eq!(p95_of(Duration::from_mins(1)), "p95 ≤ 60 s");
        assert_eq!(p95_of(Duration::from_secs(90)), "p95 > 60 s");
        assert_eq!(p95(&MetricsSnapshot::default().mineskin_latency), "p95 N/A");
    }

    #[test]
    fn shows_sizes_that_round_to_1024_kib_in_mib() {
        assert_eq!(format_bytes(1_023), "1023 B");
        assert_eq!(format_bytes(1_024), "1.00 KiB");
        assert_eq!(format_bytes(1_048_570), "1023.99 KiB");
        assert_eq!(format_bytes(1_048_571), "1.00 MiB");
        assert_eq!(format_bytes(1_048_575), "1.00 MiB");
        assert_eq!(format_bytes(1_048_576), "1.00 MiB");
    }

    #[test]
    fn labels_a_slightly_late_report_with_its_nominal_period() {
        assert_eq!(format_report_period(Duration::from_secs(301)), "5 min");
        assert_eq!(
            format_report_period(Duration::from_millis(300_004)),
            "5 min"
        );
        assert_eq!(format_report_period(Duration::from_secs(599)), "10 min");
        assert_eq!(format_report_period(Duration::from_secs(10)), "1 min");
    }

    #[tokio::test]
    async fn keeps_the_webhook_token_out_of_report_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let webhook = Url::parse(&format!("{}/api/webhooks/1/secret-token", server.uri()))
            .expect("test webhook URL should be valid");

        let client = crate::http_client::builder(Duration::from_secs(2))
            .build()
            .expect("test HTTP client should build");

        let error = send_report(&client, &webhook, &MetricsSnapshot::default())
            .await
            .expect_err("a 500 response should fail the report");

        assert_eq!(
            error.status(),
            Some(reqwest::StatusCode::INTERNAL_SERVER_ERROR)
        );
        assert!(
            !error.to_string().contains("secret-token"),
            "error should not include the webhook token: {error}"
        );
    }

    #[test]
    fn sends_the_embed_timestamp_with_millisecond_precision() {
        let report = build_report(&MetricsSnapshot::default(), &no_host_stats());
        let timestamp = report
            .pointer("/embeds/0/timestamp")
            .and_then(Value::as_str)
            .expect("the embed should have a timestamp");

        let (_, fraction) = timestamp
            .strip_suffix('Z')
            .and_then(|timestamp| timestamp.rsplit_once('.'))
            .expect("the timestamp should be UTC with a fractional second");
        assert_eq!(fraction.len(), 3, "unexpected timestamp: {timestamp}");
        timestamp
            .parse::<jiff::Timestamp>()
            .expect("the timestamp should be valid ISO 8601");
    }

    #[tokio::test]
    async fn stops_while_a_report_is_in_flight() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(204).set_delay(Duration::from_mins(1)))
            .mount(&server)
            .await;
        let webhook = Url::parse(&format!("{}/api/webhooks/1/token", server.uri()))
            .expect("test webhook URL should be valid");
        let client = crate::http_client::builder(Duration::from_mins(2))
            .build()
            .expect("test HTTP client should build");
        let metrics = Arc::new(Metrics::default());
        let (shutdown, shutdown_receiver) = oneshot::channel();
        let task = tokio::spawn({
            let metrics = Arc::clone(&metrics);
            async move {
                run(
                    &client,
                    &webhook,
                    &metrics,
                    shutdown_receiver,
                    metrics.snapshot(),
                    Instant::now(),
                    Duration::from_millis(10),
                )
                .await;
            }
        });

        timeout(Duration::from_secs(10), async {
            while server
                .received_requests()
                .await
                .is_none_or(|requests| requests.is_empty())
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the reporter should send a report");
        shutdown.send(()).expect("the reporter should be running");

        timeout(Duration::from_secs(2), task)
            .await
            .expect("shutdown should not wait for the webhook response")
            .expect("the reporter task should not panic");
    }
}
