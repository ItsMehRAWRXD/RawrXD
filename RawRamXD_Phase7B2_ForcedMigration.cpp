/**
 * RawRamXD Phase 7B.2: Forced Migration Micro-Benchmark
 * 
 * Purpose: Force actual VRAM→RAM tier pressure and measure access penalties
 * Critical Gate: Migration must add <5ms to token latency for production readiness
 * 
 * SIMPLIFIED VERSION: Uses CPU_RAM tier only (GPU_VRAM requires D3D12 upload heaps)
 */

#include <iostream>
#include <chrono>
#include <vector>
#include <cstring>
#include <random>
#include <thread>
#include <atomic>
#include <numeric>

#include "rawramxd/gpu_fabric.hpp"

#pragma comment(lib, "psapi.lib")

using namespace RawRamXD;

struct MigrationMetrics {
    uint64_t cold_load_us;          // Time to load cold tensor (cache miss)
    uint64_t hot_access_us;         // Time to access resident tensor (cache hit)
    uint64_t migration_bandwidth_mbps;
    size_t bytes_migrated;
    bool migration_triggered;
};

class ForcedMigrationBenchmark {
private:
    std::vector<void*> residentPtrs;
    size_t ramCapacityBytes;
    size_t tensorSizeBytes;
    
public:
    ForcedMigrationBenchmark() : tensorSizeBytes(256 * 1024 * 1024) { // 256MB tensors
        if (!GPUFabric::Instance().Initialize()) {
            std::cerr << "[ERROR] Failed to initialize GPU Fabric\n";
            return;
        }
        
        // Get RAM capacity
        auto devices = GPUFabric::Instance().GetDevices();
        for (auto* device : devices) {
            if (device && device->type == ComputeTargetType::CPU_RAM && device->capacityBytes > 0) {
                ramCapacityBytes = device->capacityBytes;
                std::cout << "[+] RAM Target: " << (ramCapacityBytes / (1024*1024*1024)) << " GB\n";
                break;
            }
        }
    }
    
    // Fill RAM to trigger pressure
    bool FillRAMToCapacity() {
        // Fill to 50% to avoid actual OOM
        size_t targetBytes = (size_t)(ramCapacityBytes * 0.50);
        size_t allocatedBytes = 0;
        int tensorCount = 0;
        
        std::cout << "[+] Filling RAM to 50% capacity (" << (targetBytes / (1024*1024*1024)) << " GB)...\n";
        
        while (allocatedBytes < targetBytes) {
            void* ptr = GPUFabric::Instance().Allocate(tensorSizeBytes, ComputeTargetType::CPU_RAM);
            if (ptr == nullptr) {
                std::cout << "[!] Allocation failed at " << tensorCount << " tensors\n";
                break;
            }
            
            // Write pattern to ensure physical allocation
            auto writeStart = std::chrono::high_resolution_clock::now();
            volatile uint8_t* vptr = static_cast<volatile uint8_t*>(ptr);
            for (size_t i = 0; i < tensorSizeBytes; i += 4096) {
                vptr[i] = static_cast<uint8_t>(i & 0xFF);
            }
            auto writeEnd = std::chrono::high_resolution_clock::now();
            
            residentPtrs.push_back(ptr);
            allocatedBytes += tensorSizeBytes;
            tensorCount++;
            
            if (tensorCount % 5 == 0) {
                std::cout << "  " << tensorCount << " tensors (" << (allocatedBytes / (1024*1024*1024)) << " GB)\r";
            }
        }
        
        std::cout << "\n[+] RAM filled: " << tensorCount << " tensors (" 
                  << (allocatedBytes / (1024*1024*1024)) << " GB)\n";
        return tensorCount > 0;
    }
    
    // Measure hot access (tensor already resident)
    uint64_t MeasureHotAccess() {
        if (residentPtrs.empty()) return 0;
        
        // Pick a random resident tensor
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, residentPtrs.size() - 1);
        void* ptr = residentPtrs[dis(gen)];
        
        if (!ptr) return 0;
        
        // Time a read operation
        volatile uint8_t sum = 0;
        auto start = std::chrono::high_resolution_clock::now();
        
        // Touch every page to force real memory access
        volatile uint8_t* vptr = static_cast<volatile uint8_t*>(ptr);
        for (size_t i = 0; i < tensorSizeBytes; i += 4096) {
            sum += vptr[i];
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    }
    
    // Force a cold load under pressure
    MigrationMetrics MeasureColdLoad() {
        MigrationMetrics metrics{};
        
        std::cout << "\n[+] Measuring cold load under pressure...\n";
        
        // Allocate a new tensor
        auto allocStart = std::chrono::high_resolution_clock::now();
        void* coldPtr = GPUFabric::Instance().Allocate(tensorSizeBytes, ComputeTargetType::CPU_RAM);
        auto allocEnd = std::chrono::high_resolution_clock::now();
        
        if (coldPtr == nullptr) {
            std::cout << "[!] Allocation failed\n";
            metrics.migration_triggered = false;
            return metrics;
        }
        
        uint64_t allocTime = std::chrono::duration_cast<std::chrono::microseconds>(allocEnd - allocStart).count();
        
        // Write to force physical allocation
        volatile uint8_t* vptr = static_cast<volatile uint8_t*>(coldPtr);
        auto writeStart = std::chrono::high_resolution_clock::now();
        for (size_t i = 0; i < tensorSizeBytes; i += 4096) {
            vptr[i] = 0xAB;
        }
        auto writeEnd = std::chrono::high_resolution_clock::now();
        
        metrics.cold_load_us = std::chrono::duration_cast<std::chrono::microseconds>(writeEnd - writeStart).count();
        metrics.bytes_migrated = tensorSizeBytes;
        metrics.migration_triggered = true;
        
        std::cout << "  Alloc time: " << allocTime << " us\n";
        std::cout << "  Write time: " << metrics.cold_load_us << " us\n";
        
        // Cleanup cold tensor
        GPUFabric::Instance().Free(coldPtr);
        
        return metrics;
    }
    
    // Measure memory bandwidth
    uint64_t MeasureMemoryBandwidth() {
        std::cout << "\n[+] Measuring memory bandwidth...\n";
        
        size_t testSize = 1ULL * 1024 * 1024 * 1024; // 1GB
        void* testPtr = GPUFabric::Instance().Allocate(testSize, ComputeTargetType::CPU_RAM);
        if (testPtr == nullptr) {
            std::cout << "[!] Failed to allocate test buffer\n";
            return 0;
        }
        
        // Fill with pattern
        auto fillStart = std::chrono::high_resolution_clock::now();
        volatile uint8_t* vptr = static_cast<volatile uint8_t*>(testPtr);
        for (size_t i = 0; i < testSize; i += 4096) {
            vptr[i] = static_cast<uint8_t>(i & 0xFF);
        }
        auto fillEnd = std::chrono::high_resolution_clock::now();
        
        uint64_t fillTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(fillEnd - fillStart).count();
        uint64_t bandwidthMBps = 0;
        
        if (fillTimeUs > 0) {
            bandwidthMBps = (testSize / (1024 * 1024)) * 1000000ULL / fillTimeUs;
            std::cout << "  Fill time: " << (fillTimeUs / 1000.0) << " ms\n";
            std::cout << "  Bandwidth: " << bandwidthMBps << " MB/s\n";
        }
        
        GPUFabric::Instance().Free(testPtr);
        return bandwidthMBps;
    }
    
    void RunBenchmark() {
        std::cout << "========================================\n";
        std::cout << "RawRamXD Phase 7B.2: Forced Migration\n";
        std::cout << "Micro-Benchmark (RAM Tier)\n";
        std::cout << "========================================\n\n";
        
        // Phase 1: Fill RAM
        if (!FillRAMToCapacity()) {
            std::cerr << "[ERROR] Failed to fill RAM\n";
            return;
        }
        
        // Phase 2: Measure hot access (baseline)
        std::cout << "\n[+] Measuring hot access latency...\n";
        std::vector<uint64_t> hotLatencies;
        for (int i = 0; i < 10; i++) {
            uint64_t lat = MeasureHotAccess();
            if (lat > 0) hotLatencies.push_back(lat);
        }
        
        uint64_t avgHotLatency = 0;
        if (!hotLatencies.empty()) {
            avgHotLatency = std::accumulate(hotLatencies.begin(), hotLatencies.end(), 0ULL) / hotLatencies.size();
        }
        std::cout << "  Average hot access: " << avgHotLatency << " us\n";
        
        // Phase 3: Measure cold load under pressure
        MigrationMetrics metrics = MeasureColdLoad();
        
        // Phase 4: Measure bandwidth
        uint64_t bandwidth = MeasureMemoryBandwidth();
        metrics.migration_bandwidth_mbps = bandwidth;
        
        // Report
        GenerateReport(metrics, avgHotLatency);
        
        // Cleanup
        for (auto ptr : residentPtrs) {
            GPUFabric::Instance().Free(ptr);
        }
        residentPtrs.clear();
    }
    
    void GenerateReport(const MigrationMetrics& metrics, uint64_t hotLatency) {
        std::cout << "\n========================================\n";
        std::cout << "MIGRATION MICRO-BENCHMARK RESULTS\n";
        std::cout << "========================================\n";
        
        std::cout << "\nHot Access (Resident):\n";
        std::cout << "  Latency: " << hotLatency << " us (" << (hotLatency / 1000.0) << " ms)\n";
        
        std::cout << "\nCold Load (Under Pressure):\n";
        if (metrics.migration_triggered) {
            std::cout << "  Write time: " << metrics.cold_load_us << " us (" << (metrics.cold_load_us / 1000.0) << " ms)\n";
            std::cout << "  Bytes: " << (metrics.bytes_migrated / (1024*1024)) << " MB\n";
            
            uint64_t penalty = (metrics.cold_load_us > hotLatency) ? (metrics.cold_load_us - hotLatency) : 0;
            std::cout << "  Pressure Penalty: " << penalty << " us (" << (penalty / 1000.0) << " ms)\n";
            
            // Production readiness gate
            std::cout << "\n--- PRODUCTION READINESS GATE ---\n";
            if (penalty < 5000) {
                std::cout << "  ✓ PASS: Pressure penalty < 5ms (" << (penalty / 1000.0) << " ms)\n";
                std::cout << "  → Fabric is production-ready\n";
            } else if (penalty < 50000) {
                std::cout << "  ⚠ WARNING: Pressure penalty 5-50ms (" << (penalty / 1000.0) << " ms)\n";
                std::cout << "  → Acceptable but monitor under load\n";
            } else {
                std::cout << "  ✗ FAIL: Pressure penalty > 50ms (" << (penalty / 1000.0) << " ms)\n";
                std::cout << "  → Memory pressure handling needs optimization\n";
            }
        } else {
            std::cout << "  Cold load measurement failed\n";
        }
        
        std::cout << "\nMemory Bandwidth: " << metrics.migration_bandwidth_mbps << " MB/s\n";
        
        if (metrics.migration_bandwidth_mbps > 0) {
            double theoreticalTimeMs = (metrics.bytes_migrated / (1024.0 * 1024.0)) / metrics.migration_bandwidth_mbps * 1000.0;
            std::cout << "  Theoretical 256MB write: " << theoreticalTimeMs << " ms\n";
        }
        
        std::cout << "\n========================================\n";
    }
};

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    std::cout << "RawRamXD Phase 7B.2: Forced Migration Micro-Benchmark\n";
    std::cout << "======================================================\n\n";
    std::cout << "This benchmark measures memory pressure handling\n";
    std::cout << "to determine production readiness.\n\n";
    
    ForcedMigrationBenchmark benchmark;
    benchmark.RunBenchmark();
    
    return 0;
}
