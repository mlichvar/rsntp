use crate::metrics::MetricsCollector;
use prometheus_client::encoding::text::encode;
use std::sync::Arc;
use std::thread;
use tiny_http::{Server, Response, Header};

#[derive(Clone)]
pub struct MetricsServer {
    metrics: Arc<MetricsCollector>,
    address: String,
}

impl MetricsServer {
    pub fn new(metrics: Arc<MetricsCollector>, address: String) -> Self {
        Self { metrics, address }
    }

    // Check for a URL parameter named `param_name` of type `T` and return its value, if any
    fn parse_query_param<T: std::str::FromStr>(url: &str, param_name: &str) -> Option<T> {
        if url.contains('?') {
            url.split('?').nth(1)
                .and_then(|query| {
                    query.split('&')
                        .find(|param| param.starts_with(&format!("{}=", param_name)))
                        .and_then(|param| param.split('=').nth(1))
                        .and_then(|value| value.parse::<T>().ok())
                })
        } else {
            None
        }
    }

    // Print out all the clients and their cache counters in CSV format
    fn handle_clients(&self, period: Option<u64>) -> Response<std::io::Cursor<Vec<u8>>> {
        let mut clients = self.metrics.client_cache.get_clients_with_counters(period);
        clients.sort_by_key(|(addr, _)| *addr);
        let mut output = clients
            .iter()
            .map(|(addr, counters)| {
                let counter_str = counters.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(",");
                format!("{},{}", addr, counter_str)
            })
            .collect::<Vec<_>>()
            .join("\n");

        if !output.is_empty() {
            output.push('\n');
        }

        Response::from_string(output)
            .with_header("Content-Type: text/plain; version=0.0.4; charset=utf-8".parse::<Header>().unwrap())
    }

    // Print out all of the metrics in prometheus format
    fn handle_metrics(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        self.metrics.update_process_metrics();
        self.metrics.update_unique_clients();
        let mut buffer = String::new();
        match encode(&mut buffer, &self.metrics.registry()) {
            Ok(_) => Response::from_string(buffer)
                .with_header("Content-Type: text/plain; version=0.0.4; charset=utf-8".parse::<Header>().unwrap()),
            Err(_) => Response::from_string("Failed to encode metrics").with_status_code(500),
        }
    }

    pub fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let server = Server::http(&self.address)?;
        println!("Metrics server listening on http://{}", self.address);

        for request in server.incoming_requests() {
            let metrics_server = self.clone();
            thread::spawn(move || {
                let response = match request.method() {
                    &tiny_http::Method::Get => {
                        let url = request.url();
                        if url.starts_with("/clients") {
                            let period = Self::parse_query_param::<u64>(url, "period");
                            metrics_server.handle_clients(period)
                        } else if url == "/metrics" {
                            metrics_server.handle_metrics()
                        } else {
                            Response::from_string("Not Found").with_status_code(404)
                        }
                    }
                    _ => Response::from_string("Not Found").with_status_code(404),
                };
                let _ = request.respond(response);
            });
        }

        Ok(())
    }
}
