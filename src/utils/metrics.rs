use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::domain::error::PassError;
use prometheus::proto::MetricType;
use prometheus::{
    self, Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};

use crate::domain::models::PassResult;

pub(crate) struct Metric<'a> {
    metrics: &'a PassMetrics,
    method: String,
    status: String,
    clock: Instant,
}

impl<'a> Drop for Metric<'a> {
    fn drop(&mut self) {
        let method = self.method.to_string();
        let status = self.status.to_string();

        let elapsed = self.clock.elapsed();
        let duration =
            (elapsed.as_secs() as f64) + f64::from(elapsed.subsec_nanos()) / 1_000_000_000_f64;
        self.metrics
            .requests_duration_seconds
            .with_label_values(&[&method, &status])
            .observe(duration);

        self.metrics
            .requests_total
            .with_label_values(&[&method, &status])
            .inc();
    }
}

impl<'a> Metric<'a> {
    pub fn new(metrics: &'a PassMetrics, method: &str) -> Self {
        Metric {
            metrics,
            method: method.to_string(),
            status: String::from(""),
            clock: Instant::now(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.clock.elapsed()
    }
}

#[derive(Clone)]
pub(crate) struct PassMetrics {
    requests_total: IntCounterVec,
    requests_duration_seconds: HistogramVec,
}

impl PassMetrics {
    pub fn new(prefix: &str, registry: &Registry) -> PassResult<Self> {
        let const_labels = HashMap::new();
        let buckets = prometheus::DEFAULT_BUCKETS.to_vec();
        let metrics = PassMetrics {
            requests_total: IntCounterVec::new(
                Opts::new(
                    format!("{}requests_total", prefix).as_str(),
                    "Total number of requests",
                )
                .const_labels(const_labels.clone()),
                &["method", "status"],
            )?,
            requests_duration_seconds: HistogramVec::new(
                HistogramOpts::new(
                    format!("{}requests_duration_seconds", prefix).as_str(),
                    "Request duration in seconds for all requests",
                )
                .buckets(buckets.to_vec())
                .const_labels(const_labels.clone()),
                &["method", "status"],
            )?,
        };
        match metrics.register(registry) {
            Ok(_) => {}
            Err(err) => {
                match err {
                    // ignore AlreadyReg errors
                    prometheus::Error::AlreadyReg => {}
                    _ => {
                        return Err(PassError::validation(
                            format!("prometheus validation {:?}", err).as_str(),
                            None,
                        ));
                    }
                }
            }
        }
        Ok(metrics)
    }

    fn register(&self, registry: &Registry) -> Result<(), prometheus::Error> {
        registry.register(Box::new(self.requests_total.clone()))?;
        registry.register(Box::new(self.requests_duration_seconds.clone()))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn get_request_total(&self, method: &str) -> i64 {
        match self
            .requests_total
            .get_metric_with_label_values(&[method, ""])
        {
            Ok(count) => count.get() as i64,
            Err(_) => 0,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn new_metric(&self, method: &str) -> Metric {
        Metric::new(self, method)
    }

    #[allow(dead_code)]
    pub(crate) fn summary(&self) -> HashMap<String, f64> {
        let mut summary = HashMap::new();
        for metric in prometheus::gather() {
            for m in metric.get_metric() {
                if !m.get_label().is_empty() && metric.get_field_type() == MetricType::HISTOGRAM {
                    if metric.get_field_type() == MetricType::HISTOGRAM {
                        summary.insert(
                            format!(
                                "{}[{}]_SUM",
                                metric.get_name(),
                                m.get_label()[0].get_value()
                            ),
                            m.get_histogram().get_sample_sum(),
                        );
                        summary.insert(
                            format!(
                                "{}[{}]_TOTAL",
                                metric.get_name(),
                                m.get_label()[0].get_value()
                            ),
                            m.get_histogram().get_sample_count() as f64,
                        );
                    } else if metric.get_field_type() == MetricType::COUNTER {
                        summary.insert(
                            format!(
                                "{}[{}]_COUNTER",
                                metric.get_name(),
                                m.get_label()[0].get_value()
                            ),
                            m.get_counter().get_value(),
                        );
                    }
                }
            }
        }
        summary
    }

    #[allow(dead_code)]
    pub(crate) fn dump(&self) -> PassResult<String> {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();

        let metric_families = prometheus::gather();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer.clone())?)
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use env_logger::Env;
    use prometheus::default_registry;
    use rand::Rng;

    use crate::utils::metrics::PassMetrics;

    #[test]
    fn test_should_add_metrics() {
        let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info"))
            .is_test(true)
            .try_init();
        let registry = &default_registry();
        let metrics1 = PassMetrics::new("source1_", registry).unwrap();
        let metrics2 = PassMetrics::new("source2_", registry).unwrap();
        let mut rng = rand::thread_rng();
        for _i in 0..100 {
            metrics1.new_metric("method1");
            thread::sleep(Duration::from_millis(rng.gen_range(1..5)));
        }
        for _i in 0..100 {
            metrics2.new_metric("method2");
            thread::sleep(Duration::from_millis(rng.gen_range(5..10)));
        }
        assert!(metrics1.register(default_registry()).is_err());
        assert_eq!(100, metrics1.get_request_total("method1"));
        assert_eq!(100, metrics2.get_request_total("method2"));
        assert!(!metrics1.dump().expect("should return dump").is_empty());
        assert!(!metrics1.summary().is_empty());
    }
}
