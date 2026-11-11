// =============================================================================
// sovereign_metrics_collector.cpp
// Phase 23A: Prometheus-compatible metrics exporter
// =============================================================================

#include "sovereign_metrics_collector.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <fstream>
#include <sstream>

// =============================================================================
// Internal Structures
// =============================================================================

struct MetricValue {
    std::map<std::string, std::string> labels;
    union {
        uint64_t counter;
        double gauge;
    };
    std::vector<uint64_t> histogram_buckets;
    uint64_t histogram_sum;
    uint64_t histogram_count;
};

struct MetricDefinition {
    std::string name;
    std::string description;
    metric_type_t type;
    std::vector<double> buckets;  // For histograms
    std::map<std::string, MetricValue> values;  // Key by label combination
};

struct MetricsCollector {
    metrics_config_t config;
    std::map<std::string, MetricDefinition> metrics;
    std::mutex mutex;
    int is_running;
    uint64_t start_time_ns;
};

// =============================================================================
// Lifecycle
// =============================================================================

SOVEREIGN_API metrics_collector_t metrics_collector_create(const metrics_config_t* config) {
    if (!config) return nullptr;
    
    auto* collector = new MetricsCollector();
    collector->config = *config;
    collector->is_running = 0;
    collector->start_time_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    
    return reinterpret_cast<metrics_collector_t>(collector);
}

SOVEREIGN_API void metrics_collector_destroy(metrics_collector_t collector) {
    if (!collector) return;
    
    auto* c = reinterpret_cast<MetricsCollector*>(collector);
    metrics_collector_stop(collector);
    delete c;
}

SOVEREIGN_API int metrics_collector_start(metrics_collector_t collector) {
    if (!collector) return -1;
    
    auto* c = reinterpret_cast<MetricsCollector*>(collector);
    c->is_running = 1;
    
    // Would start HTTP server thread here
    // Would start file flush thread here
    
    return 0;
}

SOVEREIGN_API int metrics_collector_stop(metrics_collector_t collector) {
    if (!collector) return -1;
    
    auto* c = reinterpret_cast<MetricsCollector*>(collector);
    c->is_running = 0;
    
    return 0;
}

// =============================================================================
// Metric Registration
// =============================================================================

SOVEREIGN_API int metrics_register_counter(metrics_collector_t collector,
                                           const char* name,
                                           const char* description,
                                           const metric_label_t* labels,
                                           size_t num_labels) {
    if (!collector || !name) return -1;
    
    auto* c = reinterpret_cast<MetricsCollector*>(collector);
    std::lock_guard<std::mutex> lock(c->mutex);
    
    MetricDefinition def;
    def.name = name;
    def.description = description ? description : "";
    def.type = METRIC_COUNTER;
    
    c->metrics[name] = def;
    
    return 0;
}

SOVEREIGN_API int metrics_register_gauge(metrics_collector_t collector,
                                         const char* name,
                                         const char* description,
                                         const metric_label_t* labels,
                                         size_t num_labels) {
    if (!collector || !name) return -1;
    
    auto* c = reinterpret_cast<MetricsCollector*>(collector);
    std::lock_guard<std::mutex> lock(c->mutex);
    
    MetricDefinition def;
    def.name = name;
    def.description = description ? description : "";
    def.type = METRIC_GAUGE;
    
    c->metrics[name] = def;
    
    return 0;
}

SOVEREIGN_API int metrics_register_histogram(metrics_collector_t collector,
                                               const char* name,
                                               const char* description,
                                               const double* buckets,
                                               size_t num_buckets,
                                               const metric_label_t* labels,
                                               size_t num_labels) {
    if (!collector || !name) return -1;
    
    auto* c = reinterpret_cast<MetricsCollector*>(collector);
    std::lock_guard<std::mutex> lock(c->mutex);
    
    MetricDefinition def;
    def.name = name;
    def.description = description ? description : "";
    def.type = METRIC_HISTOGRAM;
    
    if (buckets && num_buckets > 0) {
        def.buckets.assign(buckets, buckets + num_buckets);
    } else {
        // Default buckets for latency (ms)
        def.buckets = {0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10};
    }
    
    c->metrics[name] = def;
    
    return 0;
}

// =============================================================================
// Metric Updates
// =============================================================================

SOVEREIGN_API int metrics_counter_inc(metrics_collector_t collector,
                                      const char* name,
                                      const metric_label_t* labels,
                                      size_t num_labels,
                                      uint64_t delta) {
    if (!collector || !name) return -1;
    
    auto* c = reinterpret_cast<MetricsCollector*>(collector);
    std::lock_guard<std::mutex> lock(c->mutex);
    
    auto it = c->metrics.find(name);
    if (it == c->metrics.end()) return -1;
    
    // Build label key
    std::string label_key;
    for (size_t i = 0; i < num_labels; i++) {
        if (i > 0) label_key += ",";
        label_key += labels[i].key;
        label_key += "=";
        label_key += labels[i].value;
    }
    
    it->second.values[label_key].counter += delta;
    
    return 0;
}

SOVEREIGN_API int metrics_gauge_set(metrics_collector_t collector,
                                    const char* name,
                                    const metric_label_t* labels,
                                    size_t num_labels,
                                    double value) {
    if (!collector || !name) return -1;
    
    auto* c = reinterpret_cast<MetricsCollector*>(collector);
    std::lock_guard<std::mutex> lock(c->mutex);
    
    auto it = c->metrics.find(name);
    if (it == c->metrics.end()) return -1;
    
    std::string label_key;
    for (size_t i = 0; i < num_labels; i++) {
        if (i > 0) label_key += ",";
        label_key += labels[i].key;
        label_key += "=";
        label_key += labels[i].value;
    }
    
    it->second.values[label_key].gauge = value;
    
    return 0;
}

SOVEREIGN_API int metrics_histogram_observe(metrics_collector_t collector,
                                            const char* name,
                                            const metric_label_t* labels,
                                            size_t num_labels,
                                            double value) {
    if (!collector || !name) return -1;
    
    auto* c = reinterpret_cast<MetricsCollector*>(collector);
    std::lock_guard<std::mutex> lock(c->mutex);
    
    auto it = c->metrics.find(name);
    if (it == c->metrics.end()) return -1;
    
    std::string label_key;
    for (size_t i = 0; i < num_labels; i++) {
        if (i > 0) label_key += ",";
        label_key += labels[i].key;
        label_key += "=";
        label_key += labels[i].value;
    }
    
    auto& hist = it->second.values[label_key];
    
    // Initialize buckets if needed
    if (hist.histogram_buckets.empty()) {
        hist.histogram_buckets.resize(it->second.buckets.size() + 1, 0);
    }
    
    // Update buckets
    for (size_t i = 0; i < it->second.buckets.size(); i++) {
        if (value <= it->second.buckets[i]) {
            hist.histogram_buckets[i]++;
        }
    }
    hist.histogram_buckets[hist.histogram_buckets.size() - 1]++;
    
    hist.histogram_sum += (uint64_t)(value * 1000000);  // Microseconds
    hist.histogram_count++;
    
    return 0;
}

// =============================================================================
// Prometheus Export Format
// =============================================================================

SOVEREIGN_API int metrics_export_prometheus(metrics_collector_t collector,
                                            char* buffer,
                                            size_t* buffer_len) {
    if (!collector || !buffer || !buffer_len) return -1;
    
    auto* c = reinterpret_cast<MetricsCollector*>(collector);
    std::lock_guard<std::mutex> lock(c->mutex);
    
    std::ostringstream output;
    
    // Write header
    output << "# Sovereign Engine Metrics\n";
    output << "# Job: " << (c->config.job_name ? c->config.job_name : "sovereign") << "\n";
    output << "# Instance: " << (c->config.instance_id ? c->config.instance_id : "unknown") << "\n\n";
    
    // Export each metric
    for (const auto& [name, def] : c->metrics) {
        // Type annotation
        const char* type_str = "unknown";
        switch (def.type) {
            case METRIC_COUNTER: type_str = "counter"; break;
            case METRIC_GAUGE: type_str = "gauge"; break;
            case METRIC_HISTOGRAM: type_str = "histogram"; break;
            case METRIC_SUMMARY: type_str = "summary"; break;
        }
        
        output << "# TYPE " << name << " " << type_str << "\n";
        output << "# HELP " << name << " " << def.description << "\n";
        
        // Values
        for (const auto& [label_key, value] : def.values) {
            output << name;
            
            if (!label_key.empty()) {
                output << "{" << label_key << "}";
            }
            
            if (def.type == METRIC_COUNTER) {
                output << " " << value.counter;
            } else if (def.type == METRIC_GAUGE) {
                output << " " << value.gauge;
            } else if (def.type == METRIC_HISTOGRAM) {
                // For histograms, export sum and count
                output << "_sum " << value.histogram_sum / 1000000.0 << "\n";
                output << name << "_count " << value.histogram_count;
            }
            
            output << "\n";
        }
        
        output << "\n";
    }
    
    std::string str = output.str();
    size_t len = str.length();
    
    if (*buffer_len < len + 1) {
        *buffer_len = len + 1;
        return -1;  // Buffer too small
    }
    
    memcpy(buffer, str.c_str(), len + 1);
    *buffer_len = len;
    
    return 0;
}

// =============================================================================
// JSON Export
// =============================================================================

SOVEREIGN_API int metrics_export_json(metrics_collector_t collector,
                                      char* buffer,
                                      size_t* buffer_len) {
    if (!collector || !buffer || !buffer_len) return -1;
    
    auto* c = reinterpret_cast<MetricsCollector*>(collector);
    std::lock_guard<std::mutex> lock(c->mutex);
    
    std::ostringstream output;
    output << "{\n";
    output << "  \"job\": \"" << (c->config.job_name ? c->config.job_name : "sovereign") << "\",\n";
    output << "  \"instance\": \"" << (c->config.instance_id ? c->config.instance_id : "unknown") << "\",\n";
    output << "  \"metrics\": {\n";
    
    bool first_metric = true;
    for (const auto& [name, def] : c->metrics) {
        if (!first_metric) output << ",\n";
        first_metric = false;
        
        output << "    \"" << name << "\": {\n";
        output << "      \"type\": \"";
        switch (def.type) {
            case METRIC_COUNTER: output << "counter"; break;
            case METRIC_GAUGE: output << "gauge"; break;
            case METRIC_HISTOGRAM: output << "histogram"; break;
            case METRIC_SUMMARY: output << "summary"; break;
        }
        output << "\",\n";
        output << "      \"description\": \"" << def.description << "\",\n";
        output << "      \"values\": [\n";
        
        bool first_value = true;
        for (const auto& [label_key, value] : def.values) {
            if (!first_value) output << ",\n";
            first_value = false;
            
            output << "        {\"labels\": \"" << label_key << "\", ";
            
            if (def.type == METRIC_COUNTER) {
                output << "\"value\": " << value.counter;
            } else if (def.type == METRIC_GAUGE) {
                output << "\"value\": " << value.gauge;
            } else if (def.type == METRIC_HISTOGRAM) {
                output << "\"sum\": " << value.histogram_sum / 1000000.0 << ", ";
                output << "\"count\": " << value.histogram_count;
            }
            
            output << "}";
        }
        
        output << "\n      ]\n";
        output << "    }";
    }
    
    output << "\n  }\n";
    output << "}\n";
    
    std::string str = output.str();
    size_t len = str.length();
    
    if (*buffer_len < len + 1) {
        *buffer_len = len + 1;
        return -1;
    }
    
    memcpy(buffer, str.c_str(), len + 1);
    *buffer_len = len;
    
    return 0;
}

// =============================================================================
// File Output
// =============================================================================

SOVEREIGN_API int metrics_write_file(metrics_collector_t collector) {
    if (!collector) return -1;
    
    auto* c = reinterpret_cast<MetricsCollector*>(collector);
    if (!c->config.enable_file_output || !c->config.output_file) {
        return 0;
    }
    
    char buffer[65536];
    size_t len = sizeof(buffer);
    
    if (metrics_export_prometheus(collector, buffer, &len) == 0) {
        std::ofstream file(c->config.output_file);
        if (file.is_open()) {
            file.write(buffer, len);
            file.close();
        }
    }
    
    return 0;
}

// =============================================================================
// Default Sovereign Metrics
// =============================================================================

SOVEREIGN_API int metrics_register_sovereign_defaults(metrics_collector_t collector) {
    if (!collector) return -1;
    
    // Counters
    metrics_register_counter(collector, METRIC_TOKENS_GENERATED_TOTAL,
                             "Total tokens generated", nullptr, 0);
    metrics_register_counter(collector, METRIC_SWARM_MESSAGES_SENT,
                             "Total swarm messages sent", nullptr, 0);
    metrics_register_counter(collector, METRIC_SWARM_MESSAGES_RECV,
                             "Total swarm messages received", nullptr, 0);
    metrics_register_counter(collector, METRIC_SWARM_BYTES_SENT,
                             "Total bytes sent over swarm", nullptr, 0);
    metrics_register_counter(collector, METRIC_SWARM_BYTES_RECV,
                             "Total bytes received over swarm", nullptr, 0);
    
    // Gauges
    metrics_register_gauge(collector, METRIC_TOKENS_PER_SECOND,
                           "Current tokens per second", nullptr, 0);
    metrics_register_gauge(collector, METRIC_KV_CACHE_HIT_RATE,
                           "KV cache hit rate (0-1)", nullptr, 0);
    metrics_register_gauge(collector, METRIC_KV_CACHE_SIZE_BYTES,
                           "Current KV cache size in bytes", nullptr, 0);
    metrics_register_gauge(collector, METRIC_MEMORY_USAGE_BYTES,
                           "Current memory usage in bytes", nullptr, 0);
    metrics_register_gauge(collector, METRIC_ACTIVE_SESSIONS,
                           "Number of active inference sessions", nullptr, 0);
    metrics_register_gauge(collector, METRIC_WORKERS_CONNECTED,
                           "Number of connected swarm workers", nullptr, 0);
    
    // Histograms
    double latency_buckets[] = {1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000};
    metrics_register_histogram(collector, METRIC_INFERENCE_LATENCY_MS,
                               "Inference latency in milliseconds",
                               latency_buckets, 11, nullptr, 0);
    
    return 0;
}
