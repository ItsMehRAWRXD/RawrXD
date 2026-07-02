// =============================================================================
// sovereign_metrics_collector.h
// Phase 23A: Metrics Collection for Grafana/Prometheus
// =============================================================================

#ifndef SOVEREIGN_METRICS_COLLECTOR_H
#define SOVEREIGN_METRICS_COLLECTOR_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Metric Types
// =============================================================================

typedef enum {
    METRIC_COUNTER = 0,    // Monotonically increasing
    METRIC_GAUGE,          // Can go up or down
    METRIC_HISTOGRAM,      // Distribution of values
    METRIC_SUMMARY         // Calculated percentiles
} metric_type_t;

// =============================================================================
// Metric Labels
// =============================================================================

typedef struct {
    const char* key;
    const char* value;
} metric_label_t;

// =============================================================================
// Metrics Collector Handle
// =============================================================================

typedef struct MetricsCollector* metrics_collector_t;

// =============================================================================
// Configuration
// =============================================================================

typedef struct {
    uint16_t http_port;           // Port for Prometheus scrape endpoint
    uint32_t flush_interval_ms;   // How often to flush metrics
    const char* job_name;         // Job name for Prometheus
    const char* instance_id;      // Instance identifier
    int enable_http_endpoint;     // Enable HTTP server for scraping
    int enable_file_output;       // Write metrics to file
    const char* output_file;      // File path for metrics
} metrics_config_t;

// =============================================================================
// Lifecycle
// =============================================================================

SOVEREIGN_API metrics_collector_t metrics_collector_create(const metrics_config_t* config);
SOVEREIGN_API void metrics_collector_destroy(metrics_collector_t collector);
SOVEREIGN_API int metrics_collector_start(metrics_collector_t collector);
SOVEREIGN_API int metrics_collector_stop(metrics_collector_t collector);

// =============================================================================
// Metric Registration
// =============================================================================

SOVEREIGN_API int metrics_register_counter(metrics_collector_t collector,
                                           const char* name,
                                           const char* description,
                                           const metric_label_t* labels,
                                           size_t num_labels);

SOVEREIGN_API int metrics_register_gauge(metrics_collector_t collector,
                                         const char* name,
                                         const char* description,
                                         const metric_label_t* labels,
                                         size_t num_labels);

SOVEREIGN_API int metrics_register_histogram(metrics_collector_t collector,
                                               const char* name,
                                               const char* description,
                                               const double* buckets,
                                               size_t num_buckets,
                                               const metric_label_t* labels,
                                               size_t num_labels);

// =============================================================================
// Metric Updates
// =============================================================================

SOVEREIGN_API int metrics_counter_inc(metrics_collector_t collector,
                                      const char* name,
                                      const metric_label_t* labels,
                                      size_t num_labels,
                                      uint64_t delta);

SOVEREIGN_API int metrics_gauge_set(metrics_collector_t collector,
                                    const char* name,
                                    const metric_label_t* labels,
                                    size_t num_labels,
                                    double value);

SOVEREIGN_API int metrics_gauge_inc(metrics_collector_t collector,
                                    const char* name,
                                    const metric_label_t* labels,
                                    size_t num_labels,
                                    double delta);

SOVEREIGN_API int metrics_histogram_observe(metrics_collector_t collector,
                                            const char* name,
                                            const metric_label_t* labels,
                                            size_t num_labels,
                                            double value);

// =============================================================================
// Output Formats
// =============================================================================

SOVEREIGN_API int metrics_export_prometheus(metrics_collector_t collector,
                                            char* buffer,
                                            size_t* buffer_len);

SOVEREIGN_API int metrics_export_json(metrics_collector_t collector,
                                      char* buffer,
                                      size_t* buffer_len);

SOVEREIGN_API int metrics_write_file(metrics_collector_t collector);

// =============================================================================
// Pre-defined Sovereign Metrics
// =============================================================================

// Call these to register standard Sovereign Engine metrics
SOVEREIGN_API int metrics_register_sovereign_defaults(metrics_collector_t collector);

// Standard metric names
#define METRIC_TOKENS_GENERATED_TOTAL "sovereign_tokens_generated_total"
#define METRIC_TOKENS_PER_SECOND "sovereign_tokens_per_second"
#define METRIC_INFERENCE_LATENCY_MS "sovereign_inference_latency_ms"
#define METRIC_INFERENCE_LATENCY_BUCKET "sovereign_inference_latency_bucket"
#define METRIC_KV_CACHE_HIT_RATE "sovereign_kv_cache_hit_rate"
#define METRIC_KV_CACHE_SIZE_BYTES "sovereign_kv_cache_size_bytes"
#define METRIC_MEMORY_USAGE_BYTES "sovereign_memory_usage_bytes"
#define METRIC_ACTIVE_SESSIONS "sovereign_active_sessions"
#define METRIC_WORKERS_CONNECTED "sovereign_workers_connected"
#define METRIC_SWARM_MESSAGES_SENT "sovereign_swarm_messages_sent_total"
#define METRIC_SWARM_MESSAGES_RECV "sovereign_swarm_messages_recv_total"
#define METRIC_SWARM_BYTES_SENT "sovereign_swarm_bytes_sent_total"
#define METRIC_SWARM_BYTES_RECV "sovereign_swarm_bytes_recv_total"

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_METRICS_COLLECTOR_H
