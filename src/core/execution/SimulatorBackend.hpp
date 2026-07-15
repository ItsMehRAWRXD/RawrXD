// ============================================================================
// Simulator Backend
// ============================================================================
// Deterministic simulation backend for testing and development
// No actual model loading - produces predictable outputs
// ============================================================================

#pragma once

#include "IExecutionBackend.hpp"
#include "ExecutionRequest.hpp"
#include "ExecutionResult.hpp"

#include <random>
#include <chrono>
#include <atomic>

namespace RawrXD {
namespace Execution {

// ============================================================================
// Simulation Profile
// ============================================================================
// Configurable timing characteristics for deterministic testing
// ============================================================================

struct SimulationProfile {
    // Timing (microseconds per stage)
    uint64_t tokenize_time_us = 100;
    uint64_t inference_time_per_token_us = 5000;  // 5ms per token
    uint64_t sampling_time_us = 50;
    uint64_t detokenize_time_us = 100;
    
    // Throughput characteristics
    double tokens_per_second = 200.0;
    double prompt_tokens_per_second = 1000.0;
    
    // Memory (bytes)
    uint64_t model_memory_bytes = 2ULL * 1024 * 1024 * 1024;  // 2GB
    uint64_t kv_cache_per_token = 512 * 1024;  // 512KB per token
    
    // Output characteristics
    float temperature_variance = 0.1f;
    bool deterministic_output = true;
    
    // Predefined profiles
    static SimulationProfile Fast() {
        SimulationProfile p;
        p.inference_time_per_token_us = 1000;  // 1ms/token
        p.tokens_per_second = 1000.0;
        return p;
    }
    
    static SimulationProfile Realistic() {
        SimulationProfile p;
        p.inference_time_per_token_us = 5000;  // 5ms/token
        p.tokens_per_second = 200.0;
        return p;
    }
    
    static SimulationProfile Slow() {
        SimulationProfile p;
        p.inference_time_per_token_us = 20000;  // 20ms/token
        p.tokens_per_second = 50.0;
        return p;
    }
};

// ============================================================================
// Simulator Backend Implementation
// ============================================================================

class SimulatorBackend : public IExecutionBackend {
public:
    explicit SimulatorBackend(const SimulationProfile& profile = SimulationProfile::Realistic());
    ~SimulatorBackend() override;
    
    // IExecutionBackend implementation
    const char* GetName() const override { return "simulator"; }
    const char* GetVersion() const override { return "1.0.0"; }
    
    bool Initialize() override;
    void Shutdown() override;
    bool IsInitialized() const override { return initialized_; }
    
    bool SupportsModel(const std::string& model_path) const override;
    bool SupportsStreaming() const override { return true; }
    bool SupportsCancellation() const override { return true; }
    
    ExecutionResult Execute(const ExecutionRequest& request) override;
    bool ExecuteAsync(const ExecutionRequest& request,
                     TokenCallback on_token,
                     CompletionCallback on_complete) override;
    
    void Cancel() override;
    bool IsHealthy() const override { return initialized_; }
    
    // Simulator-specific
    void SetProfile(const SimulationProfile& profile) { profile_ = profile; }
    const SimulationProfile& GetProfile() const { return profile_; }

private:
    SimulationProfile profile_;
    bool initialized_ = false;
    std::atomic<bool> cancelled_{false};
    
    // Deterministic random for reproducible outputs
    std::mt19937 rng_{42};
    
    // Generate simulated output
    std::string GenerateOutput(const ExecutionRequest& request);
    
    // Simulate token generation with timing
    void SimulateTokenGeneration(const ExecutionRequest& request,
                                   TokenCallback on_token);
    
    // Calculate telemetry from simulation
    ExecutionTelemetry CalculateTelemetry(const ExecutionRequest& request,
                                          uint64_t start_time_us);
};

} // namespace Execution
} // namespace RawrXD
