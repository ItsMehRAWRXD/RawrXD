#pragma once
// ============================================================================
// resizeable_model.h — Dynamic Subnetwork Activation
// Models that lose and gain weight. Unused parts get UNWEIGHTED.
// Only the main attraction has weight.
// ============================================================================

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <cstdint>
#include <algorithm>
#include <cmath>
#include <chrono>

namespace rawrxd {
namespace resizeable {

// ============================================================================
// Weight State
// ============================================================================
enum class WeightState {
    Dormant = 0,      // Unloaded, no memory allocated
    Loading = 1,      // DMA/SSD -> RAM/VRAM in progress
    Active = 2,       // Fully resident, weighted
    Cooling = 3,      // Decay in progress, usage dropping
    Evicting = 4      // Being unloaded
};

// ============================================================================
// Device Location
// ============================================================================
enum class DeviceLocation {
    None = 0,
    CPU = 1,
    VRAM = 2,
    SSD = 3
};

// ============================================================================
// Weight Group — A logical subnetwork that can be independently activated
// ============================================================================
struct WeightGroup {
    std::string name;
    std::string type;          // "attention", "ffn", "embedding", "norm", "output"
    WeightState state = WeightState::Dormant;
    DeviceLocation location = DeviceLocation::None;

    float activation_score = 0.0f;  // Current activation level (0-1)
    float usage_score = 0.0f;      // Accumulated usage over time
    float magnitude = 0.0f;        // Weight magnitude (for display)
    uint64_t parameter_count = 0;
    uint64_t last_used_step = 0;
    uint64_t use_count = 0;

    // Tensor metadata (for GGUF-backed loading)
    std::vector<std::string> tensor_names;
    uint64_t memory_bytes = 0;

    // GGUF source info
    uint64_t file_offset = 0;
    uint64_t file_size = 0;
};

// ============================================================================
// Task Profile — Maps task types to preferred weight groups
// ============================================================================
struct TaskProfile {
    std::string task_type;           // "math", "code", "reasoning", "creative", "planning"
    std::vector<std::string> main_attractions;  // Primary groups to activate
    std::vector<std::string> supporting;        // Secondary groups
    float min_weighted_fraction = 0.3f;         // Minimum % to keep active
};

// ============================================================================
// ResizeableModel — Dynamic subnetwork activation engine
// ============================================================================
class ResizeableModel {
public:
    ResizeableModel();
    ~ResizeableModel() = default;

    // Initialization
    void Initialize(uint64_t total_params, uint64_t memory_budget_bytes);
    void AddGroup(const WeightGroup& group);
    void SetTaskProfiles(const std::vector<TaskProfile>& profiles);

    // Core operations
    std::vector<std::string> SelectExperts(const std::string& task_type);
    void RecordInference(const std::vector<std::string>& activated_groups);
    void StepDecay();

    // Budget management
    bool EnforceBudget();
    uint64_t CurrentMemoryUsage() const;
    uint64_t MemoryBudget() const { return m_memoryBudget; }
    void SetMemoryBudget(uint64_t bytes) { m_memoryBudget = bytes; }

    // Statistics
    size_t GroupCount() const { return m_groups.size(); }
    size_t ActiveGroupCount() const;
    uint64_t TotalParams() const { return m_totalParams; }
    uint64_t WeightedParams() const;
    double MemorySavedFraction() const;

    // Access
    const std::vector<WeightGroup>& Groups() const { return m_groups; }
    std::vector<WeightGroup>& Groups() { return m_groups; }
    const WeightGroup* FindGroup(const std::string& name) const;

    // Callbacks for real loading/unloading
    using LoadCallback = std::function<bool(const std::string& group_name)>;
    using UnloadCallback = std::function<bool(const std::string& group_name)>;
    void SetLoadCallback(LoadCallback cb) { m_loadCb = cb; }
    void SetUnloadCallback(UnloadCallback cb) { m_unloadCb = cb; }

    // Serialization
    std::string ToJSON() const;
    bool FromJSON(const std::string& json);

private:
    WeightGroup* FindGroupMutable(const std::string& name);
    void ActivateGroup(const std::string& name);
    void DeactivateGroup(const std::string& name);
    std::vector<std::string> SelectByProfile(const TaskProfile& profile);

    // State
    std::vector<WeightGroup> m_groups;
    std::vector<TaskProfile> m_profiles;
    uint64_t m_totalParams = 0;
    uint64_t m_memoryBudget = 0;
    uint64_t m_step = 0;

    // Decay parameters
    float m_decayFactor = 0.97f;
    float m_activationThreshold = 0.05f;
    float m_minWeightedFraction = 0.10f;

    // Callbacks
    LoadCallback m_loadCb;
    UnloadCallback m_unloadCb;
};

} // namespace resizeable
} // namespace rawrxd
