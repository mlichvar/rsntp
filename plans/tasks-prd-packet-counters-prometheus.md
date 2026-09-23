# Tasks: Prometheus Packet Counters for NTP Server

## Relevant Files

- `plans/prd-packet-counters-prometheus.md` - PRD containing high level description and implementation guidelines
- `src/metrics/mod.rs` - Main metrics module with MetricsCollector struct and all Prometheus functionality
- `src/metrics/events.rs` - Enums for PacketEvent, GaugeEvent, and HistogramEvent with string conversion
- `src/metrics/client_cache.rs` - TTL cache implementation for unique client tracking with configurable limits
- `src/metrics/http_server.rs` - HTTP server for `/metrics` endpoint using hyper (placeholder)
- `src/main.rs` - Command line argument parsing and metrics initialization (to be updated)
- `Cargo.toml` - Dependencies for prometheus_client, moka, and hyper crates
- `tests/metrics_test.rs` - Integration tests for metrics functionality (to be created)
- `tests/client_cache_test.rs` - Unit tests for client cache functionality (to be created)

### Notes

- Use `cargo test` to run all tests
- Use `cargo test metrics` to run metrics-specific tests
- Metrics should have zero performance impact when disabled

## Tasks

- [x] 1. Set up Dependencies and Project Structure
  - [x] 1.1 Add prometheus_client, moka, and hyper dependencies to Cargo.toml
  - [x] 1.2 Create src/metrics/ directory structure
  - [x] 1.3 Create src/metrics/mod.rs with public module declarations
  - [x] 1.4 Create placeholder files for events.rs, client_cache.rs, and http_server.rs

- [x] 2. Implement Core Metrics Module
  - [x] 2.1 Define PacketEvent, GaugeEvent, and HistogramEvent enums in events.rs
  - [x] 2.2 Implement MetricsCollector struct with Prometheus registry and metrics
  - [x] 2.3 Add thread-safe counter increment functions with thread_id parameter
  - [x] 2.4 Add gauge update functions for first_seen_time and last_seen_time
  - [x] 2.5 Add histogram recording function for packet sizes
  - [x] 2.6 Implement TTL cache for unique client tracking in client_cache.rs
  - [x] 2.7 Add client IP tracking function with automatic gauge updates
  - [x] 2.8 Ensure all metric operations ignore errors and have zero impact when disabled

- [x] 3. Add Command Line Interface Support
  - [x] 3.1 Add --metrics-port parameter to clap configuration in main.rs
  - [x] 3.2 Add --client-cache-limits parameter with default "64K,1M,16M"
  - [x] 3.3 Parse client cache limits into separate values for minute/hour/day
  - [x] 3.4 Pass metrics configuration to MetricsCollector constructor

- [x] 4. Implement HTTP Metrics Endpoint
  - [x] 4.1 Create HTTP server using std::net in http_server.rs
  - [x] 4.2 Implement /metrics endpoint that returns Prometheus format
  - [x] 4.3 Start HTTP server in separate lower-priority thread
  - [x] 4.4 Handle server startup and shutdown gracefully

- [x] 5. Integrate Metrics into Main Application
  - [x] 5.1 Initialize MetricsCollector in main.rs when --metrics-port is provided
  - [x] 5.2 Add metric recording calls to NTP server packet handling code
  - [x] 5.3 Record packet events for all server operations (receive, send, errors)
  - [x] 5.4 Record client IP addresses for unique client tracking
  - [x] 5.5 Record packet sizes for histogram metrics
  - [x] 5.6 Ensure metrics calls are conditional and have no impact when disabled
