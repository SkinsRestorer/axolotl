use std::{
    collections::HashMap,
    fs,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use reqwest::Url;
use serde_json::json;
use tokio::{
    sync::oneshot,
    task::JoinHandle,
    time::{MissedTickBehavior, interval},
};
use tracing::{error, info};

use crate::metrics::{EndpointSnapshot, Metrics, MetricsSnapshot};

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

        let (shutdown, mut shutdown_receiver) = oneshot::channel();
        let initial_snapshot = metrics.snapshot();
        let reporter_started_at = Instant::now();
        let task = tokio::spawn(async move {
            let client = match reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .https_only(true)
                .build()
            {
                Ok(client) => client,
                Err(error) => {
                    error!(%error, "Could not create Discord HTTP client");
                    return;
                }
            };
            let mut ticker = interval(REPORT_INTERVAL);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            ticker.tick().await;
            let mut last_successful_snapshot = initial_snapshot;
            let mut last_successful_report_at = reporter_started_at;

            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_receiver => break,
                    _ = ticker.tick() => {
                        let now = Instant::now();
                        let current_snapshot = metrics.snapshot();
                        let report = current_snapshot.since(
                            &last_successful_snapshot,
                            now.saturating_duration_since(last_successful_report_at),
                        );
                        match send_report(&client, &webhook, &report).await {
                            Ok(()) => {
                                metrics.acknowledge_client_requests(&current_snapshot);
                                last_successful_snapshot = current_snapshot;
                                last_successful_report_at = now;
                            }
                            Err(error) => {
                                error!(%error, "Failed to send Discord status report");
                            }
                        }
                    },
                }
            }
        });
        info!("Discord status reporter started");
        Self {
            shutdown: Some(shutdown),
            task: Some(task),
        }
    }

    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take()
            && let Err(error) = task.await
        {
            error!(%error, "Discord status reporter stopped unexpectedly");
        }
    }
}

async fn send_report(
    client: &reqwest::Client,
    webhook: &Url,
    snapshot: &MetricsSnapshot,
) -> Result<(), reqwest::Error> {
    client
        .post(webhook.clone())
        .json(&build_report(snapshot))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

fn build_report(snapshot: &MetricsSnapshot) -> serde_json::Value {
    let client_insight = ClientInsight::from_snapshot(snapshot);
    let report_period = format_report_period(snapshot.report_period);

    json!({
        "embeds": [{
            "title": "Axolotl - Status Report",
            "color": report_color(snapshot),
            "fields": [
                {
                    "name": "Server",
                    "value": server_stats(snapshot),
                    "inline": false
                },
                {
                    "name": format!("Traffic ({report_period})"),
                    "value": traffic_stats(snapshot),
                    "inline": false
                },
                {
                    "name": format!("Uploads ({report_period})"),
                    "value": format_endpoint_stats(&snapshot.upload),
                    "inline": false
                },
                {
                    "name": format!("Decryptions ({report_period})"),
                    "value": format_endpoint_stats(&snapshot.decrypt),
                    "inline": false
                },
                {
                    "name": format!("Other Endpoints ({report_period})"),
                    "value": other_endpoint_stats(snapshot),
                    "inline": true
                },
                {
                    "name": format!("Clients ({report_period})"),
                    "value": client_stats(snapshot, &client_insight),
                    "inline": true
                },
                {
                    "name": format!("MineSkin ({report_period})"),
                    "value": mineskin_stats(snapshot),
                    "inline": false
                }
            ],
            "timestamp": jiff::Timestamp::now().to_string(),
            "footer": { "text": format!("Axolotl v{}", env!("CARGO_PKG_VERSION")) }
        }]
    })
}

fn report_color(snapshot: &MetricsSnapshot) -> u32 {
    match snapshot
        .server_errors
        .saturating_add(snapshot.mineskin_errors)
    {
        0 => 0x002e_cc71,
        1..=5 => 0x00f3_9c12,
        _ => 0x00e7_4c3c,
    }
}

fn server_stats(snapshot: &MetricsSnapshot) -> String {
    let rss = process_rss_bytes().map_or_else(|| "Unavailable".to_owned(), format_bytes);
    let load_average = load_average().unwrap_or_else(|| "Unavailable".to_owned());
    format!(
        "**Uptime:** {}\n**RSS:** {rss}\n**Load Avg:** {load_average}",
        format_duration(snapshot.uptime)
    )
}

fn traffic_stats(snapshot: &MetricsSnapshot) -> String {
    let errors = snapshot
        .client_errors
        .saturating_add(snapshot.server_errors);
    let error_percentage = percentage(errors, snapshot.requests);
    format!(
        "**Requests:** {}\n**Successful:** {}\n**Redirects:** {}\n**4xx:** {}\n**5xx:** {}\n**Error rate:** {error_percentage:.1}%\n**Latency:** {} avg / {} p50 / {} p95",
        format_number(snapshot.requests),
        format_number(snapshot.successful_responses),
        format_number(snapshot.redirects),
        format_number(snapshot.client_errors),
        format_number(snapshot.server_errors),
        format_latency(snapshot.request_latency.average()),
        format_latency(snapshot.request_latency.percentile(50)),
        format_latency(snapshot.request_latency.percentile(95))
    )
}

fn format_endpoint_stats(snapshot: &EndpointSnapshot) -> String {
    let errors = snapshot
        .client_errors
        .saturating_add(snapshot.server_errors);
    let error_percentage = percentage(errors, snapshot.requests);
    let client_insight = ClientInsight::from_requests(&snapshot.client_requests);
    format!(
        "**Requests:** {}\n**Successful:** {}\n**4xx:** {}\n**5xx:** {}\n**Error rate:** {error_percentage:.1}%\n**Latency:** {} avg / {} p50 / {} p95\n**Pattern:** {}\n**Unique IPs:** {}\n**Attributed:** {} / {}\n**One-request IPs:** {} ({:.1}%)\n**Top IP:** {} req ({:.1}%)\n**Top 5 IPs:** {} req ({:.1}%)\n**Avg/IP:** {:.1}",
        format_number(snapshot.requests),
        format_number(snapshot.successful_responses),
        format_number(snapshot.client_errors),
        format_number(snapshot.server_errors),
        format_latency(snapshot.latency.average()),
        format_latency(snapshot.latency.percentile(50)),
        format_latency(snapshot.latency.percentile(95)),
        client_insight.pattern,
        format_number(client_insight.unique_clients),
        format_number(client_insight.attributed_requests),
        format_number(snapshot.requests),
        format_number(client_insight.one_request_clients),
        client_insight.one_request_client_percentage,
        format_number(client_insight.top_client_requests),
        client_insight.top_client_percentage,
        format_number(client_insight.top_five_requests),
        client_insight.top_five_percentage,
        client_insight.average_requests_per_client
    )
}

fn other_endpoint_stats(snapshot: &MetricsSnapshot) -> String {
    format!(
        "**Jobs:** {}\n**Cape:** {}\n**Health:** {}\n**Docs / Other:** {}",
        format_number(snapshot.job_requests),
        format_number(snapshot.cape_requests),
        format_number(snapshot.health_requests),
        format_number(snapshot.other_requests)
    )
}

fn client_stats(snapshot: &MetricsSnapshot, insight: &ClientInsight) -> String {
    format!(
        "**Pattern:** {}\n**Unique IPs:** {}\n**Attributed:** {} / {}\n**One-request IPs:** {} ({:.1}%)\n**Top IP:** {} req ({:.1}%)\n**Top 5 IPs:** {} req ({:.1}%)\n**Avg/IP:** {:.1}",
        insight.pattern,
        format_number(insight.unique_clients),
        format_number(insight.attributed_requests),
        format_number(snapshot.requests),
        format_number(insight.one_request_clients),
        insight.one_request_client_percentage,
        format_number(insight.top_client_requests),
        insight.top_client_percentage,
        format_number(insight.top_five_requests),
        insight.top_five_percentage,
        insight.average_requests_per_client
    )
}

fn mineskin_stats(snapshot: &MetricsSnapshot) -> String {
    let error_percentage = percentage(snapshot.mineskin_errors, snapshot.mineskin_requests);
    format!(
        "**Requests:** {}\n**Errors:** {} ({error_percentage:.1}%)\n**Rate limits:** {}\n**Received:** {}\n**Latency:** {} avg / {} p50 / {} p95",
        format_number(snapshot.mineskin_requests),
        format_number(snapshot.mineskin_errors),
        format_number(snapshot.mineskin_rate_limits),
        format_bytes(snapshot.bytes_received_from_mineskin),
        format_latency(snapshot.mineskin_latency.average()),
        format_latency(snapshot.mineskin_latency.percentile(50)),
        format_latency(snapshot.mineskin_latency.percentile(95))
    )
}

#[derive(Debug, PartialEq)]
struct ClientInsight {
    pattern: &'static str,
    unique_clients: u64,
    attributed_requests: u64,
    one_request_clients: u64,
    one_request_client_percentage: f64,
    top_client_requests: u64,
    top_client_percentage: f64,
    top_five_requests: u64,
    top_five_percentage: f64,
    average_requests_per_client: f64,
}

impl ClientInsight {
    #[allow(clippy::cast_precision_loss)]
    fn from_snapshot(snapshot: &MetricsSnapshot) -> Self {
        Self::from_requests(&snapshot.client_requests)
    }

    #[allow(clippy::cast_precision_loss)]
    fn from_requests(requests: &HashMap<IpAddr, u64>) -> Self {
        let mut request_counts = requests.values().copied().collect::<Vec<_>>();
        request_counts.sort_unstable_by(|left, right| right.cmp(left));

        let unique_clients = u64::try_from(request_counts.len()).unwrap_or(u64::MAX);
        let attributed_requests = request_counts.iter().copied().sum::<u64>();
        let one_request_clients =
            u64::try_from(request_counts.iter().filter(|count| **count == 1).count())
                .unwrap_or(u64::MAX);
        let top_client_requests = request_counts.first().copied().unwrap_or_default();
        let top_five_requests = request_counts.iter().take(5).copied().sum::<u64>();
        let top_client_percentage = percentage(top_client_requests, attributed_requests);
        let top_five_percentage = percentage(top_five_requests, attributed_requests);
        let one_request_client_percentage = percentage(one_request_clients, unique_clients);
        let average_requests_per_client = if unique_clients == 0 {
            0.0
        } else {
            attributed_requests as f64 / unique_clients as f64
        };
        let pattern = match () {
            () if attributed_requests == 0 => "No IP data",
            () if unique_clients == 1 => "Single client",
            () if top_client_percentage >= 60.0 => "One dominant client",
            () if unique_clients >= 20 && top_five_percentage >= 80.0 => "Few dominant clients",
            () if unique_clients >= 20
                && one_request_client_percentage >= 60.0
                && top_client_percentage < 20.0 =>
            {
                "Broadly distributed"
            }
            () if unique_clients <= 5 => "Small client pool",
            () => "Mixed distribution",
        };

        Self {
            pattern,
            unique_clients,
            attributed_requests,
            one_request_clients,
            one_request_client_percentage,
            top_client_requests,
            top_client_percentage,
            top_five_requests,
            top_five_percentage,
            average_requests_per_client,
        }
    }
}

#[allow(clippy::cast_precision_loss)]
fn percentage(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 / total as f64 * 100.0
    }
}

#[allow(clippy::cast_precision_loss)]
fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    match bytes {
        0..=1023 => format!("{bytes} B"),
        1024..=1_048_575 => format!("{:.2} KiB", bytes as f64 / KIB),
        _ => format!("{:.2} MiB", bytes as f64 / MIB),
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
    let minutes = duration.as_secs().div_ceil(60);
    format!("{minutes}min")
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

fn format_latency(duration: Duration) -> String {
    if duration.is_zero() {
        return "N/A".to_owned();
    }
    if duration < Duration::from_secs(1) {
        return format!("{} ms", duration.as_millis());
    }

    format!("{:.2} s", duration.as_secs_f64())
}

fn process_rss_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let kibibytes = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;
    kibibytes.checked_mul(1024)
}

fn load_average() -> Option<String> {
    let load_average = fs::read_to_string("/proc/loadavg").ok()?;
    let values = load_average.split_whitespace().take(3).collect::<Vec<_>>();
    (values.len() == 3).then(|| values.join(" / "))
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::IpAddr, str::FromStr};

    use super::{ClientInsight, MetricsSnapshot};

    #[test]
    fn identifies_distributed_and_dominant_client_traffic() {
        let distributed_counts = (1_u8..=20)
            .map(|suffix| {
                (
                    IpAddr::from_str(&format!("192.0.2.{suffix}"))
                        .expect("test IP should be valid"),
                    1,
                )
            })
            .collect::<HashMap<_, _>>();
        let distributed = ClientInsight::from_snapshot(&MetricsSnapshot {
            client_requests: distributed_counts,
            ..MetricsSnapshot::default()
        });
        assert_eq!(distributed.pattern, "Broadly distributed");
        assert_eq!(distributed.unique_clients, 20);
        assert_eq!(distributed.one_request_clients, 20);
        assert!((distributed.top_client_percentage - 5.0).abs() < f64::EPSILON);

        let dominant = ClientInsight::from_snapshot(&MetricsSnapshot {
            client_requests: HashMap::from([
                (
                    IpAddr::from_str("192.0.2.1").expect("test IP should be valid"),
                    80,
                ),
                (
                    IpAddr::from_str("192.0.2.2").expect("test IP should be valid"),
                    20,
                ),
            ]),
            ..MetricsSnapshot::default()
        });
        assert_eq!(dominant.pattern, "One dominant client");
        assert_eq!(dominant.top_client_requests, 80);
        assert!((dominant.top_client_percentage - 80.0).abs() < f64::EPSILON);
    }
}
