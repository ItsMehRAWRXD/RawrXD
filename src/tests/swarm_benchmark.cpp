// =============================================================================
// swarm_benchmark.cpp
// Phase 23A: High-Performance Swarm Benchmark
// Outputs: Real-time Prometheus + CSV for analysis
// =============================================================================

#include "../swarm/sovereign_swarm_head.h"
#include "../swarm/sovereign_swarm_worker.h"
#include "../telemetry/sovereign_metrics_collector.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <chrono>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <math.h>

// =============================================================================
// Benchmark Configuration
// =============================================================================

struct BenchmarkConfig {
    int num_workers = 2;
    int context_length = 128 * 1024;  // 128K
    int layers_per_worker = 8;
    int total_layers = 32;
    int batch_size = 1;
    int duration_seconds = 60;
    int warmup_seconds = 5;
    
    // Output
    const char* csv_path = "swarm_benchmark.csv";
    const char* prometheus_port = "9090";
    bool enable_prometheus = true;
    bool enable_csv = true;
    int csv_interval_ms = 100;  // Sample every 100ms
    
    // ZMQ tuning
    int zmq_hwm = 10000;  // Increased for 128K context
    int ring_buffer_size = 16;
};

// =============================================================================
// High-Resolution Timer
// =============================================================================

class HighResTimer {
public:
    HighResTimer() {
        QueryPerformanceFrequency(&freq_);
    }
    
    void start() {
        QueryPerformanceCounter(&start_);
    }
    
    double elapsed_ns() {
        LARGE_INTEGER end;
        QueryPerformanceCounter(&end);
        return (double)(end.QuadPart - start_.QuadPart) * 1e9 / freq_.QuadPart;
    }
    
    double elapsed_us() {
        return elapsed_ns() / 1000.0;
    }
    
    double elapsed_ms() {
        return elapsed_ns() / 1e6;
    }
    
private:
    LARGE_INTEGER freq_;
    LARGE_INTEGER start_;
};

// =============================================================================
// CSV Logger
// =============================================================================

class CSVLogger {
public:
    CSVLogger(const char* path) : file_(path) {
        // Write header
        file_ << "timestamp_ms,elapsed_ms,iteration,tokens_generated,";
        file_ << "latency_us,tps_instant,tps_avg,workers_ready,";
        file_ << "kv_transfers,cpu_percent,memory_mb,ring_buffer_size\n";
        file_.flush();
    }
    
    void log(uint64_t timestamp_ms, double elapsed_ms, uint64_t iteration,
             uint64_t tokens, double latency_us, double tps_instant, double tps_avg,
             int workers_ready, uint64_t kv_transfers, double cpu, double memory_mb,
             size_t ring_size) {
        
        file_ << timestamp_ms << ","
           << std::fixed << std::setprecision(3) << elapsed_ms << ","
           << iteration << ","
           << tokens << ","
           << std::setprecision(2) << latency_us << ","
           << std::setprecision(2) << tps_instant << ","
           << std::setprecision(2) << tps_avg << ","
           << workers_ready << ","
           << kv_transfers << ","
           << std::setprecision(1) << cpu << ","
           << std::setprecision(1) << memory_mb << ","
           << ring_size << "\n";
        
        file_.flush();
    }
    
private:
    std::ofstream file_;
};

// =============================================================================
// Benchmark Results
// =============================================================================

struct BenchmarkResults {
    double total_duration_ms;
    uint64_t total_tokens;
    double avg_tps;
    double peak_tps;
    double p50_latency_us;
    double p99_latency_us;
    double min_latency_us;
    double max_latency_us;
    uint64_t total_kv_transfers;
    double avg_cpu_percent;
    double peak_memory_mb;
};

// =============================================================================
// Swarm Benchmark Class
// =============================================================================

class SwarmBenchmark {
public:
    SwarmBenchmark(const BenchmarkConfig& config) : config_(config) {}
    
    int Run() {
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  Sovereign Swarm Benchmark                                     ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n\n");
        
        printf("Configuration:\n");
        printf("  Workers: %d\n", config_.num_workers);
        printf("  Context: %d tokens\n", config_.context_length);
        printf("  Layers per worker: %d\n", config_.layers_per_worker);
        printf("  Duration: %d seconds\n", config_.duration_seconds);
        printf("  ZMQ HWM: %d\n", config_.zmq_hwm);
        printf("\n");
        
        // Initialize metrics collector
        if (config_.enable_prometheus) {
            metrics_config_t mc = {};
            mc.http_port = atoi(config_.prometheus_port);
            mc.job_name = "swarm_benchmark";
            mc.instance_id = "benchmark-01";
            mc.enable_http_endpoint = 1;
            
            metrics_collector_ = metrics_collector_create(&mc);
            metrics_register_sovereign_defaults(metrics_collector_);
            metrics_collector_start(metrics_collector_);
            
            printf("✓ Prometheus metrics on port %s\n", config_.prometheus_port);
        }
        
        // Initialize CSV logger
        if (config_.enable_csv) {
            csv_logger_ = new CSVLogger(config_.csv_path);
            printf("✓ CSV logging to %s\n", config_.csv_path);
        }
        
        // Run benchmark
        printf("\nStarting benchmark in 3 seconds...\n");
        Sleep(3000);
        
        RunBenchmark();
        
        // Print results
        PrintResults();
        
        // Cleanup
        if (metrics_collector_) {
            metrics_collector_destroy(metrics_collector_);
        }
        if (csv_logger_) {
            delete csv_logger_;
        }
        
        return 0;
    }
    
private:
    BenchmarkConfig config_;
    metrics_collector_t metrics_collector_ = nullptr;
    CSVLogger* csv_logger_ = nullptr;
    BenchmarkResults results_ = {};
    
    std::vector<double> latency_samples_;
    HighResTimer timer_;
    
    void RunBenchmark() {
        printf("\n[Warmup] %d seconds...\n", config_.warmup_seconds);
        Sleep(config_.warmup_seconds * 1000);
        
        printf("[Benchmark] Running for %d seconds...\n\n", config_.duration_seconds);
        
        timer_.start();
        uint64_t start_time_ms = GetTickCount64();
        uint64_t last_csv_log = 0;
        
        uint64_t iteration = 0;
        uint64_t tokens_generated = 0;
        
        // Main benchmark loop
        while (true) {
            double elapsed_ms = timer_.elapsed_ms();
            
            if (elapsed_ms >= config_.duration_seconds * 1000) {
                break;
            }
            
            // Simulate inference iteration
            HighResTimer iter_timer;
            iter_timer.start();
            
            // Simulate token generation (would be actual inference)
            uint64_t tokens_this_iter = SimulateInference();
            tokens_generated += tokens_this_iter;
            iteration++;
            
            double latency_us = iter_timer.elapsed_us();
            latency_samples_.push_back(latency_us);
            
            // Calculate TPS
            double tps_instant = (latency_us > 0) ? (tokens_this_iter * 1e6 / latency_us) : 0;
            double tps_avg = (elapsed_ms > 0) ? (tokens_generated * 1000.0 / elapsed_ms) : 0;
            
            // Update Prometheus metrics
            if (metrics_collector_) {
                metrics_counter_inc(metrics_collector_, 
                    METRIC_TOKENS_GENERATED_TOTAL, nullptr, 0, tokens_this_iter);
                metrics_gauge_set(metrics_collector_,
                    METRIC_TOKENS_PER_SECOND, nullptr, 0, tps_avg);
                metrics_histogram_observe(metrics_collector_,
                    METRIC_INFERENCE_LATENCY_MS, nullptr, 0, latency_us / 1000.0);
            }
            
            // Log to CSV
            if (csv_logger_ && (elapsed_ms - last_csv_log) >= config_.csv_interval_ms) {
                csv_logger_->log(
                    GetTickCount64(),
                    elapsed_ms,
                    iteration,
                    tokens_generated,
                    latency_us,
                    tps_instant,
                    tps_avg,
                    config_.num_workers,  // Would be actual ready workers
                    iteration,  // Would be actual KV transfers
                    0.0,  // Would be actual CPU
                    0.0,  // Would be actual memory
                    0     // Would be actual ring buffer size
                );
                last_csv_log = elapsed_ms;
            }
            
            // Real-time console output every second
            if (iteration % 10 == 0) {
                printf("\r[%.1fs] Tokens: %llu | TPS: %.2f (avg) / %.2f (inst) | Latency: %.2f us",
                       elapsed_ms / 1000.0,
                       tokens_generated,
                       tps_avg,
                       tps_instant,
                       latency_us);
                fflush(stdout);
            }
        }
        
        printf("\n\n");
        
        // Calculate final results
        results_.total_duration_ms = timer_.elapsed_ms();
        results_.total_tokens = tokens_generated;
        results_.avg_tps = (results_.total_duration_ms > 0) ? 
            (results_.total_tokens * 1000.0 / results_.total_duration_ms) : 0;
        
        // Calculate percentiles
        if (!latency_samples_.empty()) {
            std::sort(latency_samples_.begin(), latency_samples_.end());
            
            results_.min_latency_us = latency_samples_.front();
            results_.max_latency_us = latency_samples_.back();
            results_.p50_latency_us = latency_samples_[latency_samples_.size() * 0.5];
            results_.p99_latency_us = latency_samples_[latency_samples_.size() * 0.99];
            
            // Peak TPS from min latency
            results_.peak_tps = (results_.min_latency_us > 0) ? 
                (1e6 / results_.min_latency_us) : 0;
        }
    }
    
    uint64_t SimulateInference() {
        // Simulate work - in real implementation this would call sovereign.dll
        // Sleep for ~1ms to simulate inference time
        Sleep(1);
        return config_.batch_size;
    }
    
    void PrintResults() {
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  Benchmark Results                                             ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n\n");
        
        printf("Duration:        %.2f seconds\n", results_.total_duration_ms / 1000.0);
        printf("Total Tokens:    %llu\n", results_.total_tokens);
        printf("\n");
        
        printf("Throughput:\n");
        printf("  Average:       %.2f TPS\n", results_.avg_tps);
        printf("  Peak:          %.2f TPS\n", results_.peak_tps);
        printf("\n");
        
        printf("Latency:\n");
        printf("  Min:           %.2f us\n", results_.min_latency_us);
        printf("  P50:           %.2f us\n", results_.p50_latency_us);
        printf("  P99:           %.2f us\n", results_.p99_latency_us);
        printf("  Max:           %.2f us\n", results_.max_latency_us);
        printf("\n");
        
        printf("Samples:         %zu latency measurements\n", latency_samples_.size());
        printf("\n");
        
        if (config_.enable_csv) {
            printf("CSV output:      %s\n", config_.csv_path);
        }
        if (config_.enable_prometheus) {
            printf("Prometheus:      http://localhost:%s/metrics\n", config_.prometheus_port);
        }
        
        printf("\n");
        
        // Performance assessment
        if (results_.avg_tps >= 2000) {
            printf("✓ EXCELLENT: Exceeded 2,000 TPS target\n");
        } else if (results_.avg_tps >= 1000) {
            printf("✓ GOOD: Met 1,000+ TPS threshold\n");
        } else if (results_.avg_tps >= 500) {
            printf("⚠ FAIR: Below 1,000 TPS target\n");
        } else {
            printf("✗ POOR: Significantly below target\n");
        }
    }
};

// =============================================================================
// Main
// =============================================================================

int main(int argc, char* argv[]) {
    BenchmarkConfig config;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) {
            config.num_workers = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--context") == 0 && i + 1 < argc) {
            config.context_length = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            config.duration_seconds = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            config.csv_path = argv[++i];
        } else if (strcmp(argv[i], "--no-prometheus") == 0) {
            config.enable_prometheus = false;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Sovereign Swarm Benchmark\n");
            printf("Usage: %s [options]\n\n", argv[0]);
            printf("Options:\n");
            printf("  --workers N       Number of workers (default: %d)\n", config.num_workers);
            printf("  --context N       Context length in tokens (default: %d)\n", config.context_length);
            printf("  --duration N       Benchmark duration in seconds (default: %d)\n", config.duration_seconds);
            printf("  --csv PATH         CSV output path (default: %s)\n", config.csv_path);
            printf("  --no-prometheus    Disable Prometheus metrics\n");
            printf("  --help             Show this help\n");
            return 0;
        }
    }
    
    SwarmBenchmark benchmark(config);
    return benchmark.Run();
}
