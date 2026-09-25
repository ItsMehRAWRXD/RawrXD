#pragma once
// ============================================================================
// GpuScheduler.hpp — Dual-GPU policy scheduler for Deep2
// Implements: SINGLE, FLIP_TOKEN, FLIP_LAYER, PIPELINE_LAYER,
//             SPLIT_EXPERT, AGENT_AFFINITY, ADAPTIVE
// ============================================================================

#include "Beaconism.hpp"
#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <unordered_map>
#include <cmath>

namespace Deep2 {

// Forward declaration
class VulkanCompute;

// ---------------------------------------------------------------------------
// GPU device descriptor
// ---------------------------------------------------------------------------
struct GpuDeviceDescriptor {
    std::string name;           // "R9700", "7800XT", etc.
    uint32_t ordinal = 0;     // Vulkan physical device ordinal
    size_t vramTotalBytes = 0;
    size_t vramFreeBytes = 0;
    uint32_t computeUnits = 0;
    float computeCapability = 0.0f;  // Relative score
    bool discrete = false;
    bool available = false;
};

// ---------------------------------------------------------------------------
// Work item descriptor
// ---------------------------------------------------------------------------
struct GpuWorkItem {
    enum Type {
        TOKEN_FULL,      // Complete token forward pass
        TOKEN_LAYER,     // Single layer within a token
        EXPERT_COMPUTE,  // Single expert evaluation
        KV_UPDATE,       // KV cache write
        LOGITS,          // Final logits GEMV
        SSM_STEP         // Selective scan step
    };
    Type type = TOKEN_FULL;
    uint32_t tokenId = 0;
    uint32_t layerId = 0;
    uint32_t expertId = 0;
    size_t bytesEstimate = 0;
    uint64_t readyTimestampNs = 0;
    std::string targetDevice;  // Preferred device (from affinity)
    bool requiresResidency = false;
    std::vector<std::string> requiredTensors;
};

// ---------------------------------------------------------------------------
// Scheduling policy
// ---------------------------------------------------------------------------
enum class GpuPolicy : uint32_t {
    SINGLE = 0,           // GPU0 only
    FLIP_TOKEN,           // Alternate entire tokens GPU0/GPU1
    FLIP_LAYER,           // Alternate layers within a token
    PIPELINE_LAYER,       // True pipeline: GPU0 layers N, GPU1 layers N+1 concurrently
    SPLIT_EXPERT,         // Split MoE experts across GPUs
    AGENT_AFFINITY,       // Bind agent to GPU, steal if idle
    ADAPTIVE,             // Score-based dynamic selection
    COUNT
};

const char* GpuPolicyName(GpuPolicy p);

// ---------------------------------------------------------------------------
// Device score for ADAPTIVE policy
// ---------------------------------------------------------------------------
struct DeviceScore {
    std::string deviceName;
    float computeCost = 0.0f;
    float transferCost = 0.0f;
    float residencyCost = 0.0f;
    float queueDelay = 0.0f;
    float totalScore = 0.0f;
    bool tensorResident = false;
    bool expertResident = false;
};

// ---------------------------------------------------------------------------
// Scheduler state
// ---------------------------------------------------------------------------
struct GpuSchedulerState {
    uint64_t tokensScheduled = 0;
    uint64_t gpu0Tokens = 0;
    uint64_t gpu1Tokens = 0;
    uint64_t handoffs = 0;
    uint64_t handoffBytes = 0;
    uint64_t handoffNs = 0;
    uint64_t queueImbalances = 0;
    uint64_t residencyMisses = 0;
    uint64_t lastTokenDevice0 = 0;  // Last token handled by GPU0
    uint64_t lastTokenDevice1 = 0;  // Last token handled by GPU1
    uint32_t currentFlipToken = 0;  // For FLIP_TOKEN/FLIP_LAYER
};

// ---------------------------------------------------------------------------
// GPU Scheduler
// ---------------------------------------------------------------------------
class GpuScheduler {
public:
    GpuScheduler();
    ~GpuScheduler();

    // Initialize with available devices
    void registerDevice(const GpuDeviceDescriptor& desc);
    void clearDevices();

    // Policy control
    void setPolicy(GpuPolicy policy);
    GpuPolicy currentPolicy() const { return policy_; }
    void setPolicyFromEnv();  // Reads DEEP2_GPU_POLICY env var

    // Schedule a work item — returns selected device name
    std::string schedule(const GpuWorkItem& work);

    // True pipeline: submit work to device without waiting
    bool submitAsync(const GpuWorkItem& work, const std::string& device);

    // Check if a device has completed previous work (for pipeline)
    bool deviceReady(const std::string& device) const;

    // Handoff: transfer KV/state between devices (for FLIP_TOKEN)
    bool handoffTokenState(uint32_t tokenId,
                           const std::string& fromDevice,
                           const std::string& toDevice);

    // Expert split: distribute experts across devices
    std::vector<std::string> scheduleExperts(const std::vector<uint32_t>& expertIds,
                                                 uint32_t tokenId);

    // Agent affinity: bind an agent to a preferred device
    void setAgentAffinity(const std::string& agentId, const std::string& device);
    std::string getAgentAffinity(const std::string& agentId) const;

    // Residency tracking
    void markTensorResident(const std::string& tensorName, const std::string& device);
    void markTensorEvicted(const std::string& tensorName, const std::string& device);
    bool isTensorResident(const std::string& tensorName, const std::string& device) const;

    // Score computation (ADAPTIVE policy)
    DeviceScore scoreDevice(const std::string& deviceName, const GpuWorkItem& work) const;

    // State accessors
    const GpuSchedulerState& state() const { return state_; }
    void resetState();

    // Beaconism integration: emit scheduler decisions as beacons
    void enableBeaconism(bool enable) { beaconismEnabled_ = enable; }

    // Diagnostics
    std::string summary() const;

private:
    std::vector<GpuDeviceDescriptor> devices_;
    GpuPolicy policy_ = GpuPolicy::SINGLE;
    GpuSchedulerState state_;
    std::unordered_map<std::string, std::string> agentAffinities_;
    std::unordered_map<std::string, std::unordered_map<std::string, bool>> tensorResidency_;
    mutable std::mutex mutex_;
    bool beaconismEnabled_ = false;

    // Policy implementations
    std::string scheduleSingle(const GpuWorkItem& work);
    std::string scheduleFlipToken(const GpuWorkItem& work);
    std::string scheduleFlipLayer(const GpuWorkItem& work);
    std::string schedulePipelineLayer(const GpuWorkItem& work);
    std::string scheduleSplitExpert(const GpuWorkItem& work);
    std::string scheduleAgentAffinity(const GpuWorkItem& work);
    std::string scheduleAdaptive(const GpuWorkItem& work);

    // Helpers
    const GpuDeviceDescriptor* findDevice(const std::string& name) const;
    float estimateTransferCost(const std::string& from, const std::string& to, size_t bytes) const;
    void emitDecisionBeacon(const GpuWorkItem& work, const std::string& chosenDevice,
                            const std::vector<DeviceScore>& scores);
};

} // namespace Deep2
