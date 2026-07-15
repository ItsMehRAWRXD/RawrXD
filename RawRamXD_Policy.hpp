// =============================================================================
// RawRamXD_Policy.hpp - Pluggable Residency Policy Interface
// =============================================================================

#ifndef RAWRAMXD_POLICY_HPP
#define RAWRAMXD_POLICY_HPP

#include "RawRamXD.hpp"
#include <vector>
#include <chrono>

namespace rawramxd {

// =============================================================================
// Enhanced Telemetry for Policy Decisions
// =============================================================================

struct ResidencyMetrics {
    // Hit rates
    double vramHitRate;           // % of accesses already in VRAM
    double ramHitRate;            // % of accesses already in RAM
    double prefetchHitRate;       // % of prefetches used before eviction
    
    // Latencies (milliseconds)
    double avgPromotionLatency;   // NVMe→RAM→VRAM time
    double avgDemotionLatency;    // VRAM→RAM→NVMe time
    double p99MigrationLatency;   // 99th percentile
    
    // Async efficiency
    double asyncOverlapRatio;     // % of migrations overlapping compute
    double dmaBandwidthGBps;      // Actual DMA throughput
    
    // Prefetch accuracy
    double prefetchAccuracy;      // % of prefetches accessed
    double prefetchWaste;         // % of prefetches evicted unused
    
    // Stall analysis
    double residencyStallTimeMs;  // Time compute waited for data
    double stallFrequency;          // Stalls per second
    
    // Pressure
    float vramPressure;           // 0.0 - 1.0
    float ramPressure;
    float nvmeBandwidthUsed;      // 0.0 - 1.0
    
    // Throughput
    double currentTPS;
    double targetTPS;
    double achievedUtilization;   // GPU compute utilization
};

// =============================================================================
// Policy Interface - Pluggable Residency Decisions
// =============================================================================

class IResidencyPolicy {
public:
    virtual ~IResidencyPolicy() = default;
    
    // Core placement decision
    virtual Tier SelectTier(const RawRamXDHandle* handle, 
                          const ResidencyMetrics& metrics) = 0;
    
    // Access notification - update internal state
    virtual void OnAccess(Handle handle, size_t bytes, 
                         const ResidencyMetrics& metrics) = 0;
    
    // Pressure notification - adapt to resource constraints
    virtual void OnPressure(Tier tier, float pressureLevel,
                           const ResidencyMetrics& metrics) = 0;
    
    // Migration completion - learn from results
    virtual void OnMigrationComplete(Handle handle, Tier from, Tier to,
                                    double latencyMs, bool success) = 0;
    
    // Prefetch decision
    virtual bool ShouldPrefetch(const RawRamXDHandle* handle,
                               const ResidencyMetrics& metrics) = 0;
    
    // Eviction decision
    virtual bool ShouldEvict(const RawRamXDHandle* handle,
                            const ResidencyMetrics& metrics) = 0;
    
    // Policy name for telemetry
    virtual const char* Name() const = 0;
    
    // Policy-specific configuration
    virtual void SetParameter(const char* name, double value) = 0;
    virtual double GetParameter(const char* name) const = 0;
};

// =============================================================================
// Pre-built Policies for Different Workloads
// =============================================================================

// Policy optimized for LLM inference
class LLMInferencePolicy : public IResidencyPolicy {
public:
    LLMInferencePolicy();
    
    Tier SelectTier(const RawRamXDHandle* handle, 
                   const ResidencyMetrics& metrics) override;
    void OnAccess(Handle handle, size_t bytes, 
                 const ResidencyMetrics& metrics) override;
    void OnPressure(Tier tier, float pressureLevel,
                     const ResidencyMetrics& metrics) override;
    void OnMigrationComplete(Handle handle, Tier from, Tier to,
                            double latencyMs, bool success) override;
    bool ShouldPrefetch(const RawRamXDHandle* handle,
                       const ResidencyMetrics& metrics) override;
    bool ShouldEvict(const RawRamXDHandle* handle,
                    const ResidencyMetrics& metrics) override;
    const char* Name() const override { return "LLMInference"; }
    void SetParameter(const char* name, double value) override;
    double GetParameter(const char* name) const override;

private:
    // LLM-specific parameters
    struct {
        double kv_cache_promotion_threshold = 0.7;
        double weight_prefetch_lookahead = 3;  // layers
        double activation_keep_duration = 0.5;  // seconds
        double vram_pressure_threshold = 0.85;
    } params_;
    
    // Track layer access patterns
    std::unordered_map<Handle, uint64_t> layerAccessOrder_;
    uint64_t accessSequence_ = 0;
};

// Policy optimized for diffusion models
class DiffusionPolicy : public IResidencyPolicy {
public:
    DiffusionPolicy();
    
    Tier SelectTier(const RawRamXDHandle* handle, 
                   const ResidencyMetrics& metrics) override;
    void OnAccess(Handle handle, size_t bytes, 
                 const ResidencyMetrics& metrics) override;
    void OnPressure(Tier tier, float pressureLevel,
                     const ResidencyMetrics& metrics) override;
    void OnMigrationComplete(Handle handle, Tier from, Tier to,
                            double latencyMs, bool success) override;
    bool ShouldPrefetch(const RawRamXDHandle* handle,
                       const ResidencyMetrics& metrics) override;
    bool ShouldEvict(const RawRamXDHandle* handle,
                    const ResidencyMetrics& metrics) override;
    const char* Name() const override { return "Diffusion"; }
    void SetParameter(const char* name, double value) override;
    double GetParameter(const char* name) const override;

private:
    // Diffusion-specific: timestep-aware residency
    struct {
        double unet_block_prefetch = 2;  // blocks ahead
        double text_encoder_pin = 1;     // keep in VRAM
        double vae_decoder_pin = 1;      // keep in VRAM
    } params_;
};

// Policy optimized for multi-model serving
class MultiModelPolicy : public IResidencyPolicy {
public:
    MultiModelPolicy();
    
    Tier SelectTier(const RawRamXDHandle* handle, 
                   const ResidencyMetrics& metrics) override;
    void OnAccess(Handle handle, size_t bytes, 
                 const ResidencyMetrics& metrics) override;
    void OnPressure(Tier tier, float pressureLevel,
                     const ResidencyMetrics& metrics) override;
    void OnMigrationComplete(Handle handle, Tier from, Tier to,
                            double latencyMs, bool success) override;
    bool ShouldPrefetch(const RawRamXDHandle* handle,
                       const ResidencyMetrics& metrics) override;
    bool ShouldEvict(const RawRamXDHandle* handle,
                    const ResidencyMetrics& metrics) override;
    const char* Name() const override { return "MultiModel"; }
    void SetParameter(const char* name, double value) override;
    double GetParameter(const char* name) const override;

private:
    // Model switching aware
    struct {
        double hot_model_count = 2;      // keep N models resident
        double model_switch_predict = 1; // predict switches
        double shared_weight_pin = 1;    // keep shared weights hot
    } params_;
    
    std::unordered_map<std::string, uint64_t> modelLastUsed_;
};

// Policy optimized for training
class TrainingPolicy : public IResidencyPolicy {
public:
    TrainingPolicy();
    
    Tier SelectTier(const RawRamXDHandle* handle, 
                   const ResidencyMetrics& metrics) override;
    void OnAccess(Handle handle, size_t bytes, 
                 const ResidencyMetrics& metrics) override;
    void OnPressure(Tier tier, float pressureLevel,
                     const ResidencyMetrics& metrics) override;
    void OnMigrationComplete(Handle handle, Tier from, Tier to,
                            double latencyMs, bool success) override;
    bool ShouldPrefetch(const RawRamXDHandle* handle,
                       const ResidencyMetrics& metrics) override;
    bool ShouldEvict(const RawRamXDHandle* handle,
                    const ResidencyMetrics& metrics) override;
    const char* Name() const override { return "Training"; }
    void SetParameter(const char* name, double value) override;
    double GetParameter(const char* name) const override;

private:
    // Training-specific: gradient-aware
    struct {
        double gradient_accumulation_pin = 1;  // keep gradients hot
        double optimizer_state_ram = 1;        // optimizer in RAM
        double checkpoint_async = 1;           // async checkpointing
    } params_;
};

// =============================================================================
// Policy Factory
// =============================================================================

class PolicyFactory {
public:
    static std::unique_ptr<IResidencyPolicy> Create(const std::string& workload);
    static std::vector<std::string> AvailablePolicies();
};

} // namespace rawramxd

#endif // RAWRAMXD_POLICY_HPP