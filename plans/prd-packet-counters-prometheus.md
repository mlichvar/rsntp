# PRD: Prometheus Packet Counters for NTP Server

## Introduction/Overview

This feature adds comprehensive packet monitoring and metrics collection to the RSNTP server using Prometheus metrics. The goal is to provide operational visibility into NTP server performance and packet handling for automated monitoring systems and operations teams performing debugging tasks.

## Goals

1. **Operational Visibility**: Provide detailed metrics on packet processing events
2. **Performance Monitoring**: Track packet counts, sizes, and client diversity
3. **Debugging Support**: Enable operations teams to identify and troubleshoot issues
4. **Zero Performance Impact**: Ensure no performance degradation when metrics are disabled
5. **Thread Safety**: Support concurrent metric updates from multiple server threads

## User Stories

- **As a monitoring system**, I want to collect NTP server metrics via `/metrics` endpoint so that I can track server health and performance
- **As an operations engineer**, I want to see packet event counters so that I can identify communication issues
- **As a system administrator**, I want to monitor unique client counts so that I can understand server load patterns
- **As a developer**, I want optional metrics collection so that production performance is not impacted when monitoring is disabled

## Functional Requirements

### 1. Command Line Interface
1.1. Add `--metrics-port` parameter to specify HTTP metrics endpoint port
1.2. Add `--client-cache-limits` parameter to configure unique client cache sizes (default: 64K,1M,16M for minute,hour,day)
1.3. When `--metrics-port` is omitted, metrics collection must be completely disabled
1.4. When enabled, metrics must be exposed on `/metrics` endpoint following Prometheus conventions

### 2. Packet Event Counters
2.1. Implement `rsntp_packet_count` counter with the following packet events:
- `client_invalid_response` - Client received an invalid response
- `client_receive_failed` - Client failed to receive response
- `client_response_received` - Client received a response
- `client_send_failed` - Client send request failed
- `client_request_sent` - Client sent a request
- `server_packet_too_short` - NTP request packet too short (< 48 bytes)
- `server_receive_failed` - NTP request socket receive operation failed
- `server_request_received` - NTP request packet received
- `server_send_failed` - NTP response packet send operation failed
- `server_response_sent` - NTP response packet sent
- `server_unsupported_version` - NTP request for unsupported version

2.2. Each counter must include labels:
- `thread_id`: Thread identifier (0 for global counters)
- `packet_event`: Event type from list above

### 3. Timing Metrics
3.1. Implement `rsntp_first_seen_time` gauge (Unix nanoseconds) for each packet event
3.2. Implement `rsntp_last_seen_time` gauge (Unix nanoseconds) for each packet event
3.3. Both metrics must use same labels as `rsntp_packet_count`

### 4. Packet Size Monitoring
4.1. Implement `rsntp_packet_size_bytes` histogram for all received packets
4.2. Use histogram buckets: <48, 48-56, 56-128, 128+ bytes
4.3. Record packet size before rejecting packets that are too short
4.4. Use global counters only (no per-thread breakdown needed)

### 5. Unique Client Tracking
5.1. Implement `rsntp_unique_clients` gauge with labels:
- `period`: "minute", "hour", or "day"
- `ip_version`: "4" or "6"
5.2. Track unique IP addresses using TTL caches with configurable sizes:
- Minute cache: 64K entries (default)
- Hour cache: 1M entries (default)
- Day cache: 16M entries (default)
5.3. Cache sizes configurable via `--client-cache-limits` parameter
5.4. Count IPv4 and IPv6 addresses separately
5.5. Update gauge after each new client address is added

### 6. Thread Safety and Performance
6.1. All metrics must be thread-safe for concurrent write access
6.2. Per-thread metric updates must also increment corresponding global metric (thread_id=0)
6.3. Zero performance impact when metrics collection is disabled

### 7. Architecture Requirements
7.1. Encapsulate all metrics functionality in dedicated class/module
7.2. Prometheus implementation must be transparent to main program
7.3. Minimize code footprint in main.rs
7.4. HTTP metrics endpoint must run in separate lower-priority thread

## Non-Goals (Out of Scope)

- Real-time alerting functionality
- Metric data persistence beyond Prometheus scraping
- Custom metric aggregation beyond standard Prometheus types
- Integration with other monitoring systems besides Prometheus
- Metric authentication or access control

## Technical Considerations

### Dependencies
- Add `prometheus_client` crate for metrics collection
- Add `moka` crate for TTL caches
- Add `hyper` crate for lightweight HTTP server (commonly used, simple API, small footprint)

### Implementation Structure
- Create dedicated metrics module with three enums:
  - Counter events enum
  - Gauge events enum
  - Histogram events enum
- Expose functions for:
  - Incrementing counters (with thread_id parameter)
  - Updating gauges (with thread_id parameter)
  - Recording histogram values (with thread_id parameter)
  - Adding client IP addresses (with automatic gauge updates)

### Thread Management
- Start HTTP server thread when metrics class is instantiated
- Use lower thread priority for metrics HTTP server
- Ensure metrics writing operations remain time-critical
- Ignore all errors in metrics recording operations

## Success Metrics

- **Functional**: All packet events are accurately counted and exposed via `/metrics`
- **Performance**: Zero measurable performance impact when metrics disabled
- **Reliability**: No metric data loss under concurrent access
- **Usability**: Operations teams can successfully monitor NTP server health
- **Integration**: Monitoring systems can successfully scrape metrics endpoint

## Implementation Details

### Resolved Requirements
- **Histogram Buckets**: Use buckets <48, 48-56, 56-128, 128+ bytes for packet size
- **Cache Size Limits**: Default 64K/1M/16M for minute/hour/day, configurable via `--client-cache-limits`
- **HTTP Server**: Use `hyper` crate for lightweight HTTP server with simple API
- **Error Handling**: Ignore all errors in metrics recording operations
- **Metric Naming**: All metrics prefixed with `rsntp_`
