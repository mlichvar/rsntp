Create a PRD for adding packet counters using prometheus_client to @main.rs

1. Primary goal is to provide operational visibility

2. Target is automated monitoring systems, and operations teams doing debugging

3. The primary metric to be tracked should be called packet_count.  The following packet events should be counted:
    - Client received an invalid response
    - Client failed to receive response
    - Client received a response
    - Client send request failed
    - Client sent a request
    - NTP request received packet too short (< 48 bytes)
    - NTP requests socket receive operation failed
    - NTP request packet received
    - NTP response packet send operation failed
    - NTP response packet sent
    - NTP request received for an unsupported NTP version

4. Prometheus integration:
    - Metrics should be exposed on /metrics as per prometheus conventions
    - The HTTP port should be specified via the command line parameter "--metrics-port".  If the parameter is omitted, metrics collection should be disabled.
    - Thread id should be included as a label on packet counters; a thread id of zero should be used to indicate global counters.
    - The packet events list above must be provided as a label named "packet_event".  Create a relatively short but descriptive string for each of the above event types for use as the label value.

5. All metrics must be thread-safe, since they will be written by multiple threads at once.

6. Metrics collection is optional.  There should be no performance impact when metrics are disabled.

7. In addition to packet_count, the following metrics should be created for each packet event, with the same labels as packet_count:
    - first_seen_time (gauge, unix time as an integer number of nanoseconds)
    - last_seen_time (gauge, unix time as an integer number of nanoseconds)

    Additionally, the following global metrics should be recorded (no need to record thread-level metrics for these):
    - packet_size_bytes (histogram, integer) - this should be recorded before packets are rejected for being too short
    - unique_clients (gauge, integer count of clients) - the total number of unique IP addresses seen in the past 1 minute, in the past 1 hour, and in the past 1 day.  Use a label named "period" with the value of "day", "hour", or "minute", and a label indicating the IP version (4 or 6).  IPv4 and IPv6 should be counted separately; do not use a combined counter for both.

8. Implementation guidelines:
    - The count of unique clients should be determined by adding every client's address to each of three TTL caches using the moka crate, with the expiry time set for each different interval (minute, hour, day).
    - All metrics functionality must be encapsulated in a dedicated class; the prometheus implementation must be transparent to the main program, and the code footprint in main.rs should be as small as possible.
    - Within the dedicated class, every metric update on a particular thread must also increment the corresponding metric for thread id zero (the global metric).
    - The dedicated class should expose functions for:
        - incrementing counters, using an enum with a value for each packet event listed above
        - updating other metric types (gauge, histogram), also using an enum for each expected usage of that metric type (so there should be three enums: one for valid counters, one for valid gauges, and one for valid histograms)
        - adding a client IP address to the pool of seen addresses; internally, after adding the address to the pool, it should update the unique_clients gauge
    - Each of the above functions should accept the calling thread id as a parameter.  Zero is a valid thread id, indicating a global metric.
    - The HTTP endpoint must run in a separate thread with lower priority than the NTP server threads.  Writing metrics is time-critical; reading metrics is not.  This thread should be started when the metrics class is instantiated.

# Open questions

1. Histogram Buckets: < 48, 48 < 56, 56 < 128, 128+.
2. Cache Size Limit: 64K for minute, 1M for hour, 16M for day, but these should be configurable via the command line parameter "--client-cache-limits".
3. HTTP Server: use whatever your existing knowledge shows is commonly used, prioritise a simple API and small code footprint
4. Error Handling: errors in recording metrics should be ignored
5. Metric Naming: metrics should have the prefix "rsntp_"
