// =============================================================================
// RawRamXD_OverCapacity_Benchmark.cpp
// =============================================================================
// Stress test: Load VRAM-exceeding models, trigger tier migration,
// record TPS/latency vs residency pressure
// =============================================================================

#include "RawRamXD.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <math>
#include <fstream>
#include <signal.h>

using namespace rawramxd;
using namespace std::chrono;

// =============================================================================
// Benchmark Configuration
// =============================================================================

struct BenchmarkConfig {
    // VRAM capacity (simulated 16GB)
    size_t vram_capacity = 16ULL * 1024 * 1024 * 1024;
    
    // RAM capacity (64GB)
    size_t ram_capacity = 64ULL * 1024 * 1024 * 1024;
    
    // NVMe capacity (1TB)
    size_t nvme_capacity = 1024ULL * 1024 * 1024 * 1024;
    
    // Model sizes to test (over-capacity scenarios)
    std::vector<size_t> model_sizes = {
        18ULL * 1024 * 1024 * 1024,   // 18GB (1.125x VRAM)
        20ULL * 1024 * 1024 * 1024,   // 20GB (1.25x VRAM) - target
        24ULL * 1024 * 1024 * 1024,   // 24GB (1.5x VRAM)
        32ULL * 1024 * 1024 * 1024,   // 32GB (2x VRAM)
    };
    
    // Tensor sizes (simulate layer weights)
    size_t tensor_size = 512 * 1024 * 1024;  // 512MB per tensor
    
    // Benchmark duration per phase
    int phase_duration_seconds = 30;
    
    // Sampling rate
    int sample_interval_ms = 100;
    
    // Output files
    const char* latency_csv = "overcapacity_latency.csv";
    const char* residency_csv = "overcapacity_residency.csv";
    const char* report_txt = "overcapacity_report.txt";
};

// =============================================================================
// Telemetry Sample
// =============================================================================

struct TelemetrySample {
    uint64_t timestamp_ms;
    size_t vram_used;
    size_t ram_used;
    size_t nvme_used;
    float vram_pressure;
    uint32_t active_tensors;
    uint32_t migrations_queued;
    uint32_t migrations_completed;
    double avg_migration_time_ms;
    double tps;
    double latency_ms;
    double tokens_generated;
    size_t current_model_size;
    const char* phase_name;
};

// =============================================================================
// Over-Capacity Benchmark
// =============================================================================

class OverCapacityBenchmark {
public:
    OverCapacityBenchmark(const BenchmarkConfig& config) 
        : config_(config), running_(false) {}
    
    ~OverCapacityBenchmark() {
        stop();
    }
    
    bool initialize() {
        std::cout << "========================================\n";
        std::cout << "RawRamXD Over-Capacity Benchmark\n";
        std::cout << "========================================\n\n";
        
        // Initialize fabric
        std::cout << "[+] Initializing RawRamXD fabric...\n";
        fabric_ = std::make_unique<Fabric>(
            config_.vram_capacity,
            config_.ram_capacity,
            config_.nvme_capacity
        );
        
        std::cout << "    VRAM: " << (config_.vram_capacity / (1024*1024*1024)) << " GB\n";
        std::cout << "    RAM:  " << (config_.ram_capacity / (1024*1024*1024)) << " GB\n";
        std::cout << "    NVMe: " << (config_.nvme_capacity / (1024*1024*1024*1024)) << " TB\n\n";
        
        // Open output files
        latency_file_.open(config_.latency_csv);
        residency_file_.open(config_.residency_csv);
        
        // Write headers
        latency_file_ << "timestamp_ms,model_size_gb,vram_pressure,latency_ms,tps\n";
        residency_file_ << "timestamp_ms,model_size_gb,vram_gb,ram_gb,nvme_gb,"
                         << "vram_pressure,active_tensors,migrations_queued,"
                         << "migrations_completed,avg_migration_ms\n";
        
        return true;
    }
    
    void run() {
        running_ = true;
        
        // Run baseline test (within capacity)
        runPhase("Baseline (12GB model)", 12ULL * 1024 * 1024 * 1024);
        
        // Run over-capacity tests
        for (size_t model_size : config_.model_sizes) {
            double ratio = (double)model_size / config_.vram_capacity;
            std::string phase = "Over-capacity (" + 
                               std::to_string((int)(model_size / (1024*1024*1024))) + 
                               "GB, " + std::to_string((int)(ratio * 100)) + "% VRAM)";
            runPhase(phase.c_str(), model_size);
        }
        
        // Run extreme test (3x VRAM)
        runPhase("Extreme (48GB, 3x VRAM)", 48ULL * 1024 * 1024 * 1024);
        
        generateReport();
    }
    
    void stop() {
        running_ = false;
        
        if (latency_file_.is_open()) latency_file_.close();
        if (residency_file_.is_open()) residency_file_.close();
    }

private:
    void runPhase(const char* phase_name, size_t model_size) {
        std::cout << "\n========================================\n";
        std::cout << "Phase: " << phase_name << "\n";
        std::cout << "========================================\n";
        
        // Calculate number of tensors
        size_t num_tensors = model_size / config_.tensor_size;
        std::cout << "[+] Loading " << num_tensors << " tensors ("
                  << (model_size / (1024*1024*1024)) << " GB model)\n";
        
        // Allocate tensors
        std::vector<Handle> tensors;
        tensors.reserve(num_tensors);
        
        auto load_start = steady_clock::now();
        
        for (size_t i = 0; i < num_tensors && running_; i++) {
            auto h = fabric_>allocate(config_.tensor_size, Tier::NVMe, 128);
            if (!h.valid()) {
                std::cerr << "[!] Allocation failed at tensor " << i << "\n";
                break;
            }
            tensors.push_back(h);
            
            // Prefetch first 80% to VRAM (will trigger spill)
            if (i < num_tensors * 0.8) {
                fabric_>migrate(h, Tier::VRAM, true);
            }
            // Next 15% to RAM
            else if (i < num_tensors * 0.95) {
                fabric_>migrate(h, Tier::RAM, true);
            }
            // Rest stays in NVMe
            
            if (i % 10 == 0) {
                std::cout << "  Loaded " << i << "/" << num_tensors << " tensors\r";
                std::cout.flush();
            }
        }
        
        auto load_end = steady_clock::now();
        auto load_ms = duration_cast<milliseconds>(load_end - load_start).count();
        
        std::cout << "\n[+] Load complete in " << load_ms << " ms\n";
        std::cout << "[+] Active tensors: " << tensors.size() << "\n";
        
        // Wait for migrations to settle
        std::cout << "[+] Waiting for migrations to settle...\n";
        std::this_thread::sleep_for(seconds(2));
        
        // Run inference simulation
        std::cout << "[+] Running inference simulation for " 
                  << config_.phase_duration_seconds << " seconds...\n";
        
        auto phase_start = steady_clock::now();
        uint64_t token_count = 0;
        
        while (running_) {
            auto now = steady_clock::now();
            auto elapsed = duration_cast<seconds>(now - phase_start).count();
            
            if (elapsed >= config_.phase_duration_seconds) break;
            
            // Simulate token generation
            auto token_start = steady_clock::now();
            
            // Access random tensors (simulating layer execution)
            for (int i = 0; i < 5; i++) {
                size_t idx = rand() % tensors.size();
                auto& h = tensors[idx];
                
                // Ensure resident (triggers migration if needed)
                fabric_>ensure_in_vram(h);
                
                // Touch (updates stats)
                fabric_>touch(h);
            }
            
            auto token_end = steady_clock::now();
            auto token_latency = duration_cast<microseconds>(token_end - token_start).count() / 1000.0;
            
            token_count++;
            
            // Sample telemetry every interval
            static auto last_sample = token_start;
            if (duration_cast<milliseconds>(token_end - last_sample).count() >= config_.sample_interval_ms) {
                sampleTelemetry(token_count, token_latency, model_size, phase_name);
                last_sample = token_end;
            }
            
            // Progress bar
            if (token_count % 10 == 0) {
                int progress = (elapsed * 100) / config_.phase_duration_seconds;
                std::cout << "  Progress: " << progress << "% ("
                          << token_count << " tokens)\r";
                std::cout.flush();
            }
        }
        
        std::cout << "\n[+] Phase complete\n";
        
        // Cleanup
        std::cout << "[+] Cleaning up tensors...\n";
        for (auto& h : tensors) {
            fabric_>free(h);
        }
        
        // Wait for cleanup
        std::this_thread::sleep_for(milliseconds(500));
    }
    
    void sampleTelemetry(uint64_t token_count, double latency_ms, 
                        size_t model_size, const char* phase_name) {
        auto stats = fabric_>stats();
        
        auto now = steady_clock::now();
        auto timestamp = duration_cast<milliseconds>(
            now.time_since_epoch()).count();
        
        double tps = 0;
        if (token_count > 0) {
            // Calculate TPS from recent samples
            tps = 1000.0 / std::max(latency_ms, 1.0);
        }
        
        // Write latency data
        latency_file_ << timestamp << ","
                     << (model_size / (1024*1024*1024)) << ","
                     << std::fixed << std::setprecision(4) << stats.vram_pressure << ","
                     << std::fixed << std::setprecision(2) << latency_ms << ","
                     << std::fixed << std::setprecision(2) << tps << "\n";
        
        // Write residency data
        residency_file_ << timestamp << ","
                       << (model_size / (1024*1024*1024)) << ","
                       << (stats.vram_used / (1024*1024*1024)) << ","
                       << (stats.ram_used / (1024*1024*1024)) << ","
                       << (stats.nvme_used / (1024*1024*1024)) << ","
                       << std::fixed << std::setprecision(4) << stats.vram_pressure << ","
                       << "0,"  // active_tensors (would need to track)
                       << stats.migrations_queued << ","
                       << stats.migrations_completed << ","
                       << std::fixed << std::setprecision(2) << stats.avg_migration_time_ms << "\n";
        
        latency_file_.flush();
        residency_file_.flush();
    }
    
    void generateReport() {
        std::ofstream report(config_.report_txt);
        
        report << "RawRamXD Over-Capacity Benchmark Report\n";
        report << "========================================\n\n";
        
        report << "Configuration:\n";
        report << "  VRAM Capacity: " << (config_.vram_capacity / (1024*1024*1024)) << " GB\n";
        report << "  RAM Capacity:  " << (config_.ram_capacity / (1024*1024*1024)) << " GB\n";
        report << "  NVMe Capacity: " << (config_.nvme_capacity / (1024*1024*1024*1024)) << " TB\n";
        report << "  Tensor Size:   " << (config_.tensor_size / (1024*1024)) << " MB\n";
        report << "  Phase Duration: " << config_.phase_duration_seconds << " seconds\n\n";
        
        report << "Test Scenarios:\n";
        report << "  1. Baseline: 12GB model (75% VRAM)\n";
        report << "  2. Over-cap 1: 18GB model (112% VRAM)\n";
        report << "  3. Over-cap 2: 20GB model (125% VRAM) - TARGET\n";
        report << "  4. Over-cap 3: 24GB model (150% VRAM)\n";
        report << "  5. Over-cap 4: 32GB model (200% VRAM)\n";
        report << "  6. Extreme: 48GB model (300% VRAM)\n\n";
        
        report << "Expected Behavior:\n";
        report << "  - Baseline: Full VRAM residency, minimal latency\n";
        report << "  - 18-20GB: Partial VRAM spill to RAM, slight latency increase\n";
        report << "  - 24-32GB: Significant RAM residency, NVMe spill, degraded TPS\n";
        report << "  - 48GB: Heavy NVMe reliance, graceful degradation, no crash\n\n";
        
        report << "Output Files:\n";
        report << "  - " << config_.latency_csv << " (timestamp, pressure, latency, TPS)\n";
        report << "  - " << config_.residency_csv << " (tier usage, migrations)\n\n";
        
        report << "Analysis Instructions:\n";
        report << "  1. Import CSV files into Excel/Python/R\n";
        report << "  2. Plot latency vs vram_pressure\n";
        report << "  3. Plot TPS vs model_size\n";
        report << "  4. Identify inflection points where tier spill occurs\n";
        report << "  5. Measure recovery time after migration bursts\n\n";
        
        report.close();
        
        std::cout << "\n[+] Report generated: " << config_.report_txt << "\n";
    }
    
    const BenchmarkConfig& config_;
    std::unique_ptr<Fabric> fabric_;
    std::atomic<bool> running_;
    std::ofstream latency_file_;
    std::ofstream residency_file_;
};

// =============================================================================
// Signal Handler
// =============================================================================

static OverCapacityBenchmark* g_benchmark = nullptr;

void signalHandler(int sig) {
    std::cout << "\n[!] Caught signal " << sig << ", stopping...\n";
    if (g_benchmark) {
        g_benchmark->stop();
    }
}

// =============================================================================
// Main
// =============================================================================

int main(int argc, char* argv[]) {
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    BenchmarkConfig config;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--vram" && i + 1 < argc) {
            config.vram_capacity = std::stoull(argv[++i]) * 1024 * 1024 * 1024;
        } else if (arg == "--duration" && i + 1 < argc) {
            config.phase_duration_seconds = std::stoi(argv[++i]);
        } else if (arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [options]\n";
            std::cout << "Options:\n";
            std::cout << "  --vram <GB>      Set VRAM capacity (default: 16)\n";
            std::cout << "  --duration <s>   Phase duration in seconds (default: 30)\n";
            return 0;
        }
    }
    
    // Run benchmark
    OverCapacityBenchmark benchmark(config);
    g_benchmark = &benchmark;
    
    if (!benchmark.initialize()) {
        std::cerr << "[!] Initialization failed\n";
        return 1;
    }
    
    benchmark.run();
    
    std::cout << "\n[+] Benchmark complete\n";
    return 0;
}