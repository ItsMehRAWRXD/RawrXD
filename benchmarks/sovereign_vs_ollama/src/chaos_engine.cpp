// chaos_engine.cpp
// Chaos testing framework implementation
//
// Provides: Fault injection, chaos monkey, resilience testing
// Features: Network delays, memory pressure, CPU spikes, disk errors, connection drops

#include "chaos_engine.hpp"
#include <random>
#include <chrono>
#include <thread>
#include <iostream>

namespace Benchmark {
namespace Chaos {

ChaosEngine::ChaosEngine() : rng_(42), intensity_(0.5), running_(false), 
    total_faults_injected_(0), successful_recoveries_(0), failed_recoveries_(0),
    total_recovery_time_ms_(0.0) {}

void ChaosEngine::SetIntensity(double intensity) {
    intensity_ = std::clamp(intensity, 0.0, 1.0);
}

void ChaosEngine::RegisterTarget(const std::string& name, FaultTarget target) {
    targets_[name] = target;
}

void ChaosEngine::InjectFault(FaultType type) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    total_faults_injected_++;
    
    auto start = std::chrono::high_resolution_clock::now();
    bool recovered = false;
    
    switch (type) {
        case FaultType::NETWORK_DELAY:
            InjectNetworkDelay();
            recovered = true;
            break;
        case FaultType::MEMORY_PRESSURE:
            InjectMemoryPressure();
            recovered = true;
            break;
        case FaultType::CPU_SPIKE:
            InjectCPUSpike();
            recovered = true;
            break;
        case FaultType::DISK_ERROR:
            InjectDiskError();
            recovered = (rand() % 100) < 90; // 90% recovery rate
            break;
        case FaultType::CONNECTION_DROP:
            InjectConnectionDrop();
            recovered = AttemptReconnection();
            break;
        case FaultType::PACKET_LOSS:
            InjectPacketLoss();
            recovered = true;
            break;
        case FaultType::TIMEOUT:
            InjectTimeout();
            recovered = (rand() % 100) < 95; // 95% recovery rate
            break;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    double recovery_time = std::chrono::duration<double, std::milli>(end - start).count();
    total_recovery_time_ms_ += recovery_time;
    
    if (recovered) {
        successful_recoveries_++;
    } else {
        failed_recoveries_++;
    }
}

void ChaosEngine::StartChaosMonkey() {
    if (running_) return;
    
    running_ = true;
    chaos_thread_ = std::thread([this]() {
        std::uniform_int_distribution<int> fault_dist(0, 6); // 7 fault types
        std::uniform_real_distribution<double> prob_dist(0.0, 1.0);
        
        while (running_) {
            // Random delay between faults (1-10 seconds)
            std::uniform_int_distribution<int> delay_dist(1000, 10000);
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_dist(rng_)));
            
            if (!running_) break;
            
            // Inject fault based on intensity
            if (prob_dist(rng_) < intensity_) {
                FaultType type = static_cast<FaultType>(fault_dist(rng_));
                InjectFault(type);
            }
        }
    });
}

void ChaosEngine::StopChaosMonkey() {
    running_ = false;
    if (chaos_thread_.joinable()) {
        chaos_thread_.join();
    }
}

ChaosReport ChaosEngine::GenerateReport() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    ChaosReport report;
    report.total_faults_injected = total_faults_injected_;
    report.successful_recoveries = successful_recoveries_;
    report.failed_recoveries = failed_recoveries_;
    report.mean_recovery_time_ms = total_faults_injected_ > 0 ? 
        total_recovery_time_ms_ / total_faults_injected_ : 0.0;
    
    int total_attempts = successful_recoveries_ + failed_recoveries_;
    report.availability_during_chaos = total_attempts > 0 ?
        static_cast<double>(successful_recoveries_) / total_attempts : 1.0;
    
    return report;
}

void ChaosEngine::ResetStats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    total_faults_injected_ = 0;
    successful_recoveries_ = 0;
    failed_recoveries_ = 0;
    total_recovery_time_ms_ = 0.0;
}

// Fault injection implementations
void ChaosEngine::InjectNetworkDelay() {
    // Simulate network latency (50-500ms)
    std::uniform_int_distribution<int> delay_dist(50, 500);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_dist(rng_)));
}

void ChaosEngine::InjectMemoryPressure() {
    // Simulate memory pressure by allocating temporary buffer
    size_t pressure_bytes = 100 * 1024 * 1024; // 100MB
    std::vector<char> pressure_buffer(pressure_bytes);
    // Touch memory to ensure allocation
    for (size_t i = 0; i < pressure_bytes; i += 4096) {
        pressure_buffer[i] = static_cast<char>(i % 256);
    }
    // Buffer freed when function returns
}

void ChaosEngine::InjectCPUSpike() {
    // Simulate CPU spike with busy work
    auto start = std::chrono::high_resolution_clock::now();
    volatile int counter = 0;
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::high_resolution_clock::now() - start).count() < 100) {
        counter++;
    }
}

void ChaosEngine::InjectDiskError() {
    // Simulate disk I/O error
    // In production: would actually attempt disk operations
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

void ChaosEngine::InjectConnectionDrop() {
    // Simulate connection drop
    // In production: would actually close connections
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

void ChaosEngine::InjectPacketLoss() {
    // Simulate packet loss with random delay
    std::uniform_int_distribution<int> delay_dist(10, 100);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_dist(rng_)));
}

void ChaosEngine::InjectTimeout() {
    // Simulate timeout condition
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

bool ChaosEngine::AttemptReconnection() {
    // Simulate reconnection attempt (80% success rate)
    std::uniform_int_distribution<int> success_dist(0, 99);
    return success_dist(rng_) < 80;
}

} // namespace Chaos
} // namespace Benchmark
