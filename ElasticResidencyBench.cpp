// =============================================================================
// ElasticResidencyBench.cpp - Real Over-Capacity Benchmark
// =============================================================================
// Force-loads VRAM-exceeding models, triggers real tier migrations,
// records actual TPS/latency degradation
// =============================================================================

#include "RawRamXD_Real.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <cmath>
#include <fstream>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <atomic>
#include <thread>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace rawramxd;
using namespace std::chrono;

// =============================================================================
// Benchmark Configuration
// =============================================================================

struct Config {
    // Real memory capacities (auto-detected or specified)
    size_t vramCapacity = 0;      // 0 = auto-detect
    size_t ramCapacity = 0;         // 0 = use 75% of system
    size_t nvmeCapacity = 100ULL * 1024 * 1024 * 1024; // 100GB NVMe backing
    
    // Test scenarios
    std::vector<size_t> modelSizes;
    size_t tensorSize = 256 * 1024 * 1024;  // 256MB tensors
    
    // Timing
    int phaseDurationSec = 20;
    int sampleIntervalMs = 50;
    int warmupTokens = 10;
    
    // Output
    const char* outputDir = "elastic_residency_results";
};

// =============================================================================
// CSV Logger
// =============================================================================

class CSVLogger {
public:
    void open(const char* filename) {
        file_.open(filename);
        file_ << "timestamp_ms,phase,model_gb,vram_gb,ram_gb,nvme_gb,"
             << "vram_pressure,latency_ms,tps,tokens,migrations\n";
    }
    
    void log(uint64_t ts, const char* phase, size_t modelGB,
             const ResidencyMetrics& metrics, double latency, double tps,
             uint64_t tokens, uint32_t migrations) {
        if (!file_.is_open()) return;
        
        file_ << ts << ","
             << phase << ","
             << modelGB << ","
             << (metrics.vramUsed / (1024*1024*1024)) << ","
             << (metrics.ramUsed / (1024*1024*1024)) << ","
             << (metrics.nvmeUsed / (1024*1024*1024)) << ","
             << std::fixed << std::setprecision(4) << metrics.vramPressure << ","
             << std::fixed << std::setprecision(2) << latency << ","
             << std::fixed << std::setprecision(2) << tps << ","
             << tokens << ","
             << migrations << "\n";
        file_.flush();
    }
    
    void close() { if (file_.is_open()) file_.close(); }
    
private:
    std::ofstream file_;
};

// =============================================================================
// Elastic Residency Benchmark
// =============================================================================

class ElasticResidencyBench {
public:
    ElasticResidencyBench(const Config& cfg) : config_(cfg), running_(false) {}
    
    bool initialize() {
        std::cout << "========================================\n";
        std::cout << "RawRamXD Elastic Residency Benchmark\n";
        std::cout << "REAL MEMORY - REAL MIGRATIONS\n";
        std::cout << "========================================\n\n";
        
        // Auto-detect VRAM if not specified
        if (config_.vramCapacity == 0) {
            #ifdef HAS_CUDA
            size_t free, total;
            cudaMemGetInfo(&free, &total);
            config_.vramCapacity = total;
            std::cout << "[+] Auto-detected GPU VRAM: " 
                      << (total / (1024ULL*1024*1024)) << " GB\n";
            #else
            std::cout << "[!] CUDA not available, using simulated 16GB VRAM\n";
            config_.vramCapacity = 16ULL * 1024 * 1024 * 1024;
            #endif
        }
        
        // Auto-detect RAM if not specified
        if (config_.ramCapacity == 0) {
            #ifdef _WIN32
            MEMORYSTATUSEX memStatus;
            memStatus.dwLength = sizeof(memStatus);
            GlobalMemoryStatusEx(&memStatus);
            config_.ramCapacity = (memStatus.ullTotalPhys * 3) / 4; // Use 75%
            #else
            long pages = sysconf(_SC_PHYS_PAGES);
            long pageSize = sysconf(_SC_PAGE_SIZE);
            config_.ramCapacity = (pages * pageSize * 3) / 4;
            #endif
            std::cout << "[+] Auto-detected System RAM: " 
                      << (config_.ramCapacity / (1024ULL*1024*1024)) << " GB\n";
        }
        
        // Build model sizes based on VRAM capacity
        buildModelSizes();
        
        // Initialize fabric
        std::cout << "\n[+] Initializing RawRamXD fabric...\n";
        if (!fabric_.initialize(config_.vramCapacity, config_.ramCapacity, 
                               config_.nvmeCapacity)) {
            std::cerr << "[!] Fabric initialization failed\n";
            return false;
        }
        
        // Create output directory
        #ifdef _WIN32
        CreateDirectoryA(config_.outputDir, nullptr);
        #else
        mkdir(config_.outputDir, 0755);
        #endif
        
        // Open CSV
        char csvPath[256];
        snprintf(csvPath, sizeof(csvPath), "%s/elastic_residency.csv", config_.outputDir);
        logger_.open(csvPath);
        
        std::cout << "[+] Output: " << csvPath << "\n\n";
        return true;
    }
    
    void run() {
        running_ = true;
        
        for (size_t modelSize : config_.modelSizes) {
            if (!running_) break;
            runPhase(modelSize);
        }
        
        generateReport();
    }
    
    void stop() { running_ = false; }

private:
    void buildModelSizes() {
        size_t vramGB = config_.vramCapacity / (1024ULL*1024*1024);
        
        config_.modelSizes = {
            (vramGB * 3 / 4) * 1024ULL*1024*1024,      // 75% - Baseline
            (vramGB * 9 / 8) * 1024ULL*1024*1024,      // 112% - Light spill
            (vramGB * 5 / 4) * 1024ULL*1024*1024,      // 125% - Target spill
            (vramGB * 3 / 2) * 1024ULL*1024*1024,      // 150% - Heavy spill
            (vramGB * 2) * 1024ULL*1024*1024,          // 200% - Double
            (vramGB * 3) * 1024ULL*1024*1024,          // 300% - Extreme
        };
    }
    
    void runPhase(size_t modelSize) {
        size_t modelGB = modelSize / (1024ULL*1024*1024);
        size_t vramGB = config_.vramCapacity / (1024ULL*1024*1024);
        double ratio = (double)modelSize / config_.vramCapacity;
        
        const char* phaseName;
        if (ratio < 0.8) phaseName = "BASELINE";
        else if (ratio < 1.1) phaseName = "LIGHT_SPILL";
        else if (ratio < 1.3) phaseName = "TARGET_SPILL";
        else if (ratio < 1.6) phaseName = "HEAVY_SPILL";
        else if (ratio < 2.1) phaseName = "DOUBLE";
        else phaseName = "EXTREME";
        
        std::cout << "========================================\n";
        std::cout << "Phase: " << phaseName << "\n";
        std::cout << "Model: " << modelGB << " GB (" << (int)(ratio*100) << "% of VRAM)\n";
        std::cout << "========================================\n";
        
        // Calculate tensors
        size_t numTensors = modelSize / config_.tensorSize;
        std::cout << "[+] Allocating " << numTensors << " tensors ("
                  << (config_.tensorSize / (1024*1024)) << " MB each)\n";
        
        // Allocate tensors
        std::vector<TensorHandle*> tensors;
        tensors.reserve(numTensors);
        
        auto t1 = steady_clock::now();
        for (size_t i = 0; i < numTensors && running_; i++) {
            char name[64];
            snprintf(name, sizeof(name), "tensor_%zu", i);
            
            auto* h = fabric_.allocate(config_.tensorSize, name, Tier::NVMe);
            if (!h) {
                std::cerr << "[!] Allocation failed at tensor " << i << "\n";
                break;
            }
            tensors.push_back(h);
            
            // Promote hot tensors to VRAM (will trigger spill)
            if (i < numTensors * 0.7) {
                fabric_.migrateAsync(h, Tier::VRAM);
            } else if (i < numTensors * 0.9) {
                fabric_.migrateAsync(h, Tier::RAM);
            }
            
            if (i % 10 == 0) {
                std::cout << "  Allocated " << i << "/" << numTensors << "\r";
                std::cout.flush();
            }
        }
        auto t2 = steady_clock::now();
        
        std::cout << "\n[+] Allocated " << tensors.size() << " tensors in "
                  << duration_cast<milliseconds>(t2-t1).count() << " ms\n";
        
        // Wait for migrations to settle
        std::cout << "[+] Waiting for migrations to settle...\n";
        std::this_thread::sleep_for(seconds(3));
        
        // Show initial residency
        fabric_.dumpState();
        
        // Run inference simulation
        std::cout << "[+] Running inference for " << config_.phaseDurationSec << " seconds...\n";
        
        auto phaseStart = steady_clock::now();
        uint64_t tokenCount = 0;
        double totalLatency = 0;
        
        while (running_) {
            auto now = steady_clock::now();
            auto elapsedSec = duration_cast<seconds>(now - phaseStart).count();
            if (elapsedSec >= config_.phaseDurationSec) break;
            
            // Simulate token generation
            auto tokStart = steady_clock::now();
            
            // Access random tensors (simulates layer execution)
            for (int i = 0; i < 5; i++) {
                size_t idx = rand() % tensors.size();
                auto* h = tensors[idx];
                
                // This triggers real migration if not in VRAM
                fabric_.ensureInVRAM(h);
                fabric_.touch(h);
            }
            
            auto tokEnd = steady_clock::now();
            double tokLatency = duration_cast<microseconds>(tokEnd - tokStart).count() / 1000.0;
            totalLatency += tokLatency;
            tokenCount++;
            
            // Sample metrics
            static auto lastSample = tokStart;
            if (duration_cast<milliseconds>(tokEnd - lastSample).count() >= config_.sampleIntervalMs) {
                auto metrics = fabric_.getMetrics();
                auto history = fabric_.getMigrationHistory();
                uint32_t recentMigrations = 0;
                
                auto sampleMs = duration_cast<milliseconds>(
                    tokEnd.time_since_epoch()).count();
                double avgLat = tokenCount > 0 ? totalLatency / tokenCount : 0;
                double tps = avgLat > 0 ? 1000.0 / avgLat : 0;
                
                logger_.log(sampleMs, phaseName, modelGB, metrics, 
                           avgLat, tps, tokenCount, recentMigrations);
                
                lastSample = tokEnd;
            }
            
            // Progress
            if (tokenCount % 20 == 0) {
                int pct = (elapsedSec * 100) / config_.phaseDurationSec;
                auto metrics = fabric_.getMetrics();
                std::cout << "  Progress: " << pct << "% | "
                          << "VRAM: " << (int)(metrics.vramPressure * 100) << "% | "
                          << "Tokens: " << tokenCount << "\r";
                std::cout.flush();
            }
        }
        
        std::cout << "\n[+] Phase complete: " << tokenCount << " tokens\n";
        
        // Cleanup
        std::cout << "[+] Cleaning up...\n";
        for (auto* h : tensors) {
            fabric_.free(h);
        }
        std::this_thread::sleep_for(milliseconds(500));
    }
    
    void generateReport() {
        char reportPath[256];
        snprintf(reportPath, sizeof(reportPath), "%s/report.txt", config_.outputDir);
        
        std::ofstream report(reportPath);
        report << "RawRamXD Elastic Residency Benchmark Report\n";
        report << "==========================================\n\n";
        report << "Configuration:\n";
        report << "  VRAM: " << (config_.vramCapacity / (1024ULL*1024*1024)) << " GB\n";
        report << "  RAM:  " << (config_.ramCapacity / (1024ULL*1024*1024)) << " GB\n";
        report << "  NVMe: " << (config_.nvmeCapacity / (1024ULL*1024*1024)) << " GB\n\n";
        
        report << "Test Scenarios:\n";
        for (size_t i = 0; i < config_.modelSizes.size(); i++) {
            size_t gb = config_.modelSizes[i] / (1024ULL*1024*1024);
            double ratio = (double)config_.modelSizes[i] / config_.vramCapacity;
            report << "  " << (i+1) << ". " << gb << " GB (" << (int)(ratio*100) << "% VRAM)\n";
        }
        
        report << "\nSuccess Criteria:\n";
        report << "  - 125% VRAM: <50% latency increase\n";
        report << "  - 300% VRAM: <3x latency, no crash\n";
        report << "  - All phases: Graceful degradation curve\n\n";
        
        report.close();
        
        std::cout << "\n[+] Report: " << reportPath << "\n";
    }
    
    const Config& config_;
    RawRamXDFabric fabric_;
    std::atomic<bool> running_;
    CSVLogger logger_;
};

// =============================================================================
// Signal Handler
// =============================================================================

static ElasticResidencyBench* g_bench = nullptr;

void signalHandler(int sig) {
    std::cout << "\n[!] Signal " << sig << ", stopping...\n";
    if (g_bench) g_bench->stop();
}

// =============================================================================
// Main
// =============================================================================

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    Config config;
    
    // Parse args
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--vram") == 0 && i+1 < argc) {
            config.vramCapacity = atoll(argv[++i]) * 1024ULL * 1024 * 1024;
        } else if (strcmp(argv[i], "--duration") == 0 && i+1 < argc) {
            config.phaseDurationSec = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0) {
            std::cout << "Usage: " << argv[0] << " [options]\n";
            std::cout << "Options:\n";
            std::cout << "  --vram <GB>      Set VRAM capacity\n";
            std::cout << "  --duration <s>   Phase duration\n";
            return 0;
        }
    }
    
    ElasticResidencyBench bench(config);
    g_bench = &bench;
    
    if (!bench.initialize()) {
        return 1;
    }
    
    bench.run();
    
    std::cout << "\n[+] Benchmark complete\n";
    return 0;
}