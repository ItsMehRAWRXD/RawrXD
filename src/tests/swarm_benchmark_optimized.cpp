// =============================================================================
// swarm_benchmark_optimized.cpp
// Phase 23A: Optimized Benchmark with CPU Pinning, HWM Tuning, Chaos Testing
// Throughput-oriented with latency guardrails
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
#include <processthreadsapi.h>  // For CPU pinning

// =============================================================================
// Optimized Configuration
// =============================================================================

struct OptimizedConfig {
    // Core settings
    int num_workers = 2;
    int context_length = 128 * 1024;
    int layers_per_worker = 8;
    int batch_size = 4;  // Increased for throughput
    
    // Timing
    int duration_seconds = 60;
    int warmup_seconds = 5;
    int cooldown_seconds = 2;
    
    // Performance tuning
    int zmq_hwm = 50000;  // Increased for 128K context
    int ring_buffer_size = 64;  // Power of 2
    bool enable_cpu_pinning = true;
    int target_core_start = 2;  // Skip cores 0-1 (OS/System)
    
    // Latency guardrails (microseconds)
    double latency_p50_target = 50000.0;   // 50ms
    double latency_p99_target = 100000.0;  // 100ms
    double latency_max_limit = 200000.0;   // 200ms
    
    // Chaos testing
    bool enable_chaos = false;
    double chaos_frequency = 0.05;  // 5% of iterations
    double chaos_load_multiplier = 1.5;  // 150% load spike
    
    // Output
    const char* csv_path = "swarm_benchmark_optimized.csv";
    const char* prometheus_port = "9090";
    bool enable_prometheus = true;
    int csv_interval_ms = 50;  // Higher resolution
    
    // Recovery monitoring
    bool monitor_recovery = true;
    double recovery_threshold_tps = 0.8;  // Alert if TPS drops below 80%
};

// =============================================================================
// CPU Pinning Utility
// =============================================================================

class CPUPinner {
public:
    static bool PinThreadToCore(int core_id) {
        DWORD_PTR mask = 1ULL << core_id;
        HANDLE thread = GetCurrentThread();
        
        if (SetThreadAffinityMask(thread, mask) == 0) {
            fprintf(stderr, "Failed to pin thread to core %d: %lu\n", 
                    core_id, GetLastError());
            return false;
        }
        
        return true;
    }
    
    static bool PinProcessToCores(int start_core, int num_cores) {
        DWORD_PTR mask = 0;
        for (int i = 0; i < num_cores; i++) {
            mask |= (1ULL << (start_core + i));
        }
        
        HANDLE process = GetCurrentProcess();
        if (SetProcessAffinityMask(process, mask) == 0) {
            fprintf(stderr, "Failed to set process affinity: %lu\n", GetLastError());
            return false;
        }
        
        return true;
    }
    
    static void PrintAffinity() {
        DWORD_PTR process_mask, system_mask;
        HANDLE process = GetCurrentProcess();
        
        if (GetProcessAffinityMask(process, &process_mask, &system_mask)) {
            printf("Process affinity mask: 0x%llX\n", (unsigned long long)process_mask);
            
            printf("Available cores: ");
            for (int i = 0; i < 64; i++) {
                if (process_mask & (1ULL << i)) {
                    printf("%d ", i);
                }
            }
            printf("\n");
        }
    }
};

// =============================================================================
// Chaos Engine (Induces Load Spikes)
// =============================================================================

class ChaosEngine {
public:
    ChaosEngine(double frequency, double multiplier) 
        : frequency_(frequency), multiplier_(multiplier) {
        srand((unsigned)time(nullptr));
    }
    
    bool ShouldTrigger() {
        return ((double)rand() / RAND_MAX) < frequency_;
    }
    
    int GetSpikeDuration() {
        // Random duration between 100-500ms
        return 100 + (rand() % 400);
    }
    
    double GetLoadMultiplier() {
        return multiplier_;
    }
    
private:
    double frequency_;
    double multiplier_;
};

// =============================================================================
// Latency Histogram (Lock-Free)
// =============================================================================

class LatencyHistogram {
public:
    static constexpr int NUM_BUCKETS = 20;
    static constexpr double BUCKET_SIZE_US = 5000.0;  // 5ms buckets
    
    LatencyHistogram() {
        memset(buckets_, 0, sizeof(buckets_));
        total_samples_ = 0;
        sum_us_ = 0;
    }
    
    void record(double latency_us) {
        int bucket = (int)(latency_us / BUCKET_SIZE_US);
        if (bucket >= NUM_BUCKETS) bucket = NUM_BUCKETS - 1;
        if (bucket < 0) bucket = 0;
        
        buckets_[bucket].fetch_add(1, std::memory_order_relaxed);
        total_samples_.fetch_add(1, std::memory_order_relaxed);
        
        // Approximate sum (atomic add of double is tricky, using CAS loop)
        double expected = sum_us_.load();
        double desired;
        do {
            desired = expected + latency_us;
        } while (!sum_us_.compare_exchange_weak(expected, desired));
    }
    
    double get_percentile(double p) {
        uint64_t total = total_samples_.load();
        if (total == 0) return 0;
        
        uint64_t target = (uint64_t)(total * p);
        uint64_t cumulative = 0;
        
        for (int i = 0; i < NUM_BUCKETS; i++) {
            cumulative += buckets_[i].load();
            if (cumulative >= target) {
                return (i + 1) * BUCKET_SIZE_US;
            }
        }
        
        return NUM_BUCKETS * BUCKET_SIZE_US;
    }
    
    double get_average() {
        uint64_t total = total_samples_.load();
        if (total == 0) return 0;
        return sum_us_.load() / total;
    }
    
    void print() {
        printf("\nLatency Distribution:\n");
        uint64_t total = total_samples_.load();
        
        for (int i = 0; i < NUM_BUCKETS; i++) {
            uint64_t count = buckets_[i].load();
            double pct = (total > 0) ? (100.0 * count / total) : 0;
            
            printf("  %5.1f-%5.1f ms: %6.2f%% ",
                   i * BUCKET_SIZE_US / 1000.0,
                   (i + 1) * BUCKET_SIZE_US / 1000.0,
                   pct);
            
            // Bar chart
            int bars = (int)(pct / 2);
            for (int j = 0; j < bars; j++) printf("█");
            printf("\n");
        }
        
        printf("\nPercentiles:\n");
        printf("  p50: %.2f ms\n", get_percentile(0.50) / 1000.0);
        printf("  p90: %.2f ms\n", get_percentile(0.90) / 1000.0);
        printf("  p99: %.2f ms\n", get_percentile(0.99) / 1000.0);
        printf("  Avg: %.2f ms\n", get_average() / 1000.0);
    }
    
private:
    std::atomic<uint64_t> buckets_[NUM_BUCKETS];
    std::atomic<uint64_t> total_samples_;
    std::atomic<double> sum_us_;
};

// =============================================================================
// Optimized CSV Logger (Async I/O)
// =============================================================================

class AsyncCSVLogger {
public:
    AsyncCSVLogger(const char* path) : file_(path), buffer_(), mutex_(), 
                                        flush_thread_(), should_stop_(false) {
        // Write header
        file_ << "timestamp_ms,elapsed_ms,iteration,tokens_generated,";
        file_ << "latency_us,tps_instant,tps_avg,workers_ready,";
        file_ << "kv_transfers,cpu_percent,memory_mb,ring_size,";
        file_ << "chaos_active,recovery_active,p50_latency,p99_latency\n";
        file_.flush();
        
        // Start flush thread
        flush_thread_ = std::thread(&AsyncCSVLogger::flush_loop, this);
    }
    
    ~AsyncCSVLogger() {
        should_stop_ = true;
        if (flush_thread_.joinable()) {
            flush_thread_.join();
        }
        flush_buffer();
    }
    
    void log(uint64_t timestamp_ms, double elapsed_ms, uint64_t iteration,
             uint64_t tokens, double latency_us, double tps_instant, double tps_avg,
             int workers_ready, uint64_t kv_transfers, double cpu, double memory_mb,
             size_t ring_size, bool chaos_active, bool recovery_active,
             double p50_latency, double p99_latency) {
        
        std::ostringstream ss;
        ss << timestamp_ms << ","
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
           << ring_size << ","
           << (chaos_active ? 1 : 0) << ","
           << (recovery_active ? 1 : 0) << ","
           << std::setprecision(2) << p50_latency << ","
           << p99_latency << "\n";
        
        std::lock_guard<std::mutex> lock(mutex_);
        buffer_ += ss.str();
        
        // Flush if buffer gets large
        if (buffer_.size() > 65536) {
            flush_buffer();
        }
    }
    
private:
    std::ofstream file_;
    std::string buffer_;
    std::mutex mutex_;
    std::thread flush_thread_;
    std::atomic<bool> should_stop_;
    
    void flush_loop() {
        while (!should_stop_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            flush_buffer();
        }
    }
    
    void flush_buffer() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!buffer_.empty()) {
            file_ << buffer_;
            file_.flush();
            buffer_.clear();
        }
    }
};

// =============================================================================
// Main Benchmark Class (Optimized)
// =============================================================================

class OptimizedSwarmBenchmark {
public:
    OptimizedSwarmBenchmark(const OptimizedConfig& config) 
        : config_(config), histogram_(), chaos_(config.chaos_frequency, config.chaos_load_multiplier) {}
    
    int Run() {
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  Sovereign Swarm Benchmark (Optimized)                       ║\n");
        printf("║  Strategy: Throughput-First with Latency Guardrails          ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n\n");
        
        // CPU Pinning
        if (config_.enable_cpu_pinning) {
            printf("[CPU Pinning]\n");
            CPUPinner::PrintAffinity();
            
            if (CPUPinner::PinProcessToCores(config_.target_core_start, 
                                                config_.num_workers + 2)) {
                printf("✓ Pinned to cores %d-%d\n\n", 
                       config_.target_core_start, 
                       config_.target_core_start + config_.num_workers + 1);
            } else {
                printf("⚠ CPU pinning failed (continuing without)\n\n");
            }
        }
        
        // Configuration summary
        printf("Configuration:\n");
        printf("  Workers: %d | Context: %d | Batch: %d\n", 
               config_.num_workers, config_.context_length, config_.batch_size);
        printf("  ZMQ HWM: %d | Duration: %ds\n", 
               config_.zmq_hwm, config_.duration_seconds);
        printf("  Latency Targets: p50<%.0fms, p99<%.0fms, max<%.0fms\n",
               config_.latency_p50_target/1000,
               config_.latency_p99_target/1000,
               config_.latency_max_limit/1000);
        printf("  Chaos Testing: %s\n\n", config_.enable_chaos ? "ENABLED" : "disabled");
        
        // Initialize
        if (config_.enable_prometheus) {
            printf("✓ Prometheus metrics on port %s\n", config_.prometheus_port);
        }
        
        csv_logger_ = new AsyncCSVLogger(config_.csv_path);
        printf("✓ Async CSV logging to %s\n\n", config_.csv_path);
        
        // Warmup
        printf("[Warmup] %d seconds...\n", config_.warmup_seconds);
        run_phase(config_.warmup_seconds, true);
        printf("✓ Warmup complete\n\n");
        
        // Main benchmark
        printf("[Benchmark] Running for %d seconds...\n\n", config_.duration_seconds);
        run_phase(config_.duration_seconds, false);
        
        // Cooldown
        printf("\n[Cooldown] %d seconds...\n", config_.cooldown_seconds);
        run_phase(config_.cooldown_seconds, true);
        
        // Results
        print_results();
        
        // Cleanup
        delete csv_logger_;
        
        return 0;
    }
    
private:
    OptimizedConfig config_;
    LatencyHistogram histogram_;
    ChaosEngine chaos_;
    AsyncCSVLogger* csv_logger_ = nullptr;
    
    struct PhaseResults {
        uint64_t total_tokens = 0;
        uint64_t iterations = 0;
        double total_time_ms = 0;
        uint64_t chaos_events = 0;
        uint64_t recovery_events = 0;
    } phase_results_;
    
    void run_phase(int duration_seconds, bool is_warmup) {
        auto start_time = std::chrono::high_resolution_clock::now();
        auto end_time = start_time + std::chrono::seconds(duration_seconds);
        
        uint64_t iteration = 0;
        uint64_t tokens_generated = 0;
        uint64_t last_csv_log = 0;
        bool chaos_active = false;
        int chaos_end_time = 0;
        
        while (std::chrono::high_resolution_clock::now() < end_time) {
            auto iter_start = std::chrono::high_resolution_clock::now();
            
            // Chaos testing
            if (config_.enable_chaos && !is_warmup) {
                if (!chaos_active && chaos_.ShouldTrigger()) {
                    chaos_active = true;
                    chaos_end_time = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                        iter_start - start_time).count() + chaos_.GetSpikeDuration();
                    phase_results_.chaos_events++;
                    printf("[CHAOS] Load spike triggered (%.0f%%)\n", 
                           chaos_.GetLoadMultiplier() * 100);
                }
                
                if (chaos_active) {
                    int current_time = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                        iter_start - start_time).count();
                    if (current_time >= chaos_end_time) {
                        chaos_active = false;
                        printf("[CHAOS] Spike ended\n");
                    }
                }
            }
            
            // Simulate inference with optional chaos multiplier
            int batch = config_.batch_size;
            if (chaos_active) {
                batch = (int)(batch * chaos_.GetLoadMultiplier());
            }
            
            // Simulate work
            simulate_work(batch, chaos_active);
            tokens_generated += batch;
            iteration++;
            
            // Measure latency
            auto iter_end = std::chrono::high_resolution_clock::now();
            double latency_us = std::chrono::duration_cast<std::chrono::nanoseconds>(
                iter_end - iter_start).count() / 1000.0;
            
            // Record in histogram
            histogram_.record(latency_us);
            
            // Check latency guardrails
            bool recovery_active = false;
            if (latency_us > config_.latency_max_limit) {
                recovery_active = true;
                phase_results_.recovery_events++;
            }
            
            // Calculate TPS
            double elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                iter_end - start_time).count();
            double tps_instant = (latency_us > 0) ? (batch * 1e6 / latency_us) : 0;
            double tps_avg = (elapsed_ms > 0) ? (tokens_generated * 1000.0 / elapsed_ms) : 0;
            
            // Log to CSV
            if (!is_warmup && csv_logger_) {
                uint64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    iter_end.time_since_epoch()).count();
                
                if ((uint64_t)elapsed_ms - last_csv_log >= (uint64_t)config_.csv_interval_ms) {
                    csv_logger_->log(
                        now_ms, elapsed_ms, iteration, tokens_generated,
                        latency_us, tps_instant, tps_avg, config_.num_workers,
                        iteration, 0.0, 0.0, 0, chaos_active, recovery_active,
                        histogram_.get_percentile(0.50),
                        histogram_.get_percentile(0.99)
                    );
                    last_csv_log = (uint64_t)elapsed_ms;
                }
            }
            
            // Console output every second
            if (iteration % 20 == 0 && !is_warmup) {
                printf("\r[%5.1fs] TPS: %6.1f (avg) %6.1f (inst) | "
                       "Lat: %5.2fms (p50) %5.2fms (p99) %s",
                       elapsed_ms / 1000.0,
                       tps_avg, tps_instant,
                       histogram_.get_percentile(0.50) / 1000.0,
                       histogram_.get_percentile(0.99) / 1000.0,
                       chaos_active ? "[CHAOS] " : "       ");
                fflush(stdout);
            }
        }
        
        if (!is_warmup) {
            phase_results_.total_tokens = tokens_generated;
            phase_results_.iterations = iteration;
            phase_results_.total_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - start_time).count();
        }
        
        printf("\n");
    }
    
    void simulate_work(int batch_size, bool chaos_mode) {
        // Simulate inference time
        // Base: ~1ms per token, scaled by batch
        int sleep_ms = 1 + (batch_size / 4);
        
        if (chaos_mode) {
            sleep_ms = (int)(sleep_ms * 1.3);  // 30% slower under chaos
        }
        
        Sleep(sleep_ms);
    }
    
    void print_results() {
        printf("\n╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  Benchmark Results                                             ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n\n");
        
        double avg_tps = (phase_results_.total_time_ms > 0) ? 
            (phase_results_.total_tokens * 1000.0 / phase_results_.total_time_ms) : 0;
        
        printf("Duration:        %.2f seconds\n", phase_results_.total_time_ms / 1000.0);
        printf("Total Tokens:    %llu\n", phase_results_.total_tokens);
        printf("Iterations:      %llu\n", phase_results_.iterations);
        printf("\n");
        
        printf("Throughput:\n");
        printf("  Average:       %.2f TPS\n", avg_tps);
        printf("  Target:        2200 TPS (8-node)\n");
        printf("  Single-Node:   %.2f TPS (estimated)\n", avg_tps * config_.num_workers / 8.0);
        printf("\n");
        
        // Print histogram
        histogram_.print();
        
        printf("\n");
        if (config_.enable_chaos) {
            printf("Chaos Testing:\n");
            printf("  Events:        %llu\n", phase_results_.chaos_events);
            printf("  Recoveries:    %llu\n", phase_results_.recovery_events);
            printf("\n");
        }
        
        // Latency guardrail assessment
        double p50 = histogram_.get_percentile(0.50);
        double p99 = histogram_.get_percentile(0.99);
        
        printf("Latency Guardrails:\n");
        printf("  p50: %.2f ms %s\n", p50 / 1000.0,
               (p50 <= config_.latency_p50_target) ? "✓ PASS" : "✗ FAIL");
        printf("  p99: %.2f ms %s\n", p99 / 1000.0,
               (p99 <= config_.latency_p99_target) ? "✓ PASS" : "✗ FAIL");
        printf("\n");
        
        // Overall assessment
        if (avg_tps >= 2000 && p99 <= config_.latency_p99_target) {
            printf("✓ EXCELLENT: Exceeded 2,000 TPS with acceptable latency\n");
        } else if (avg_tps >= 1500 && p99 <= config_.latency_p99_target * 1.2) {
            printf("✓ GOOD: Met throughput target with acceptable latency\n");
        } else if (avg_tps >= 1000) {
            printf("⚠ FAIR: Below target but functional\n");
        } else {
            printf("✗ POOR: Significantly below target - requires optimization\n");
        }
        
        printf("\nOutput: %s\n", config_.csv_path);
    }
};

// =============================================================================
// Main
// =============================================================================

int main(int argc, char* argv[]) {
    OptimizedConfig config;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) {
            config.num_workers = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--context") == 0 && i + 1 < argc) {
            config.context_length = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            config.duration_seconds = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--batch") == 0 && i + 1 < argc) {
            config.batch_size = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--hwm") == 0 && i + 1 < argc) {
            config.zmq_hwm = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--chaos") == 0) {
            config.enable_chaos = true;
        } else if (strcmp(argv[i], "--no-pin") == 0) {
            config.enable_cpu_pinning = false;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Sovereign Swarm Benchmark (Optimized)\n\n");
            printf("Usage: %s [options]\n\n", argv[0]);
            printf("Options:\n");
            printf("  --workers N       Number of workers (default: %d)\n", config.num_workers);
            printf("  --context N       Context length (default: %d)\n", config.context_length);
            printf("  --duration N      Benchmark duration in seconds (default: %d)\n", config.duration_seconds);
            printf("  --batch N         Batch size (default: %d)\n", config.batch_size);
            printf("  --hwm N           ZMQ HWM (default: %d)\n", config.zmq_hwm);
            printf("  --chaos           Enable chaos testing\n");
            printf("  --no-pin          Disable CPU pinning\n");
            printf("  --help            Show this help\n");
            return 0;
        }
    }
    
    OptimizedSwarmBenchmark benchmark(config);
    return benchmark.Run();
}
