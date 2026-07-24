//============================================================================
// nevm_execution_plan_version.hpp
// RawrXD N-EVM - Execution Plan Version Tracking
// Dependency tracking for plan freshness validation
//============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <functional>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Execution Plan Version
//============================================================================

struct ExecutionPlanVersion {
    uint64_t model_hash;              // Hash of model weights/config
    uint64_t tensor_layout_hash;      // Memory layout of tensors
    uint64_t kernel_registry_hash;    // Available kernels and capabilities
    uint64_t precision_policy_hash;   // Current precision settings
    uint64_t residency_policy_hash;   // Residency management policy
    uint64_t math_mode_hash;          // Math mode configuration
    uint64_t build_timestamp;         // When plan was compiled
    
    bool operator==(const ExecutionPlanVersion& other) const {
        return model_hash == other.model_hash &&
               tensor_layout_hash == other.tensor_layout_hash &&
               kernel_registry_hash == other.kernel_registry_hash &&
               precision_policy_hash == other.precision_policy_hash &&
               residency_policy_hash == other.residency_policy_hash &&
               math_mode_hash == other.math_mode_hash;
    }
    
    bool operator!=(const ExecutionPlanVersion& other) const {
        return !(*this == other);
    }
    
    // Check if plan is compatible with current environment
    bool IsCompatibleWith(const ExecutionPlanVersion& current) const {
        // All hashes must match for compatibility
        return *this == current;
    }
    
    // Get human-readable difference description
    std::string GetDifference(const ExecutionPlanVersion& other) const {
        std::string diff;
        
        if (model_hash != other.model_hash) {
            diff += "model_hash ";
        }
        if (tensor_layout_hash != other.tensor_layout_hash) {
            diff += "tensor_layout ";
        }
        if (kernel_registry_hash != other.kernel_registry_hash) {
            diff += "kernel_registry ";
        }
        if (precision_policy_hash != other.precision_policy_hash) {
            diff += "precision_policy ";
        }
        if (residency_policy_hash != other.residency_policy_hash) {
            diff += "residency_policy ";
        }
        if (math_mode_hash != other.math_mode_hash) {
            diff += "math_mode ";
        }
        
        return diff.empty() ? "identical" : diff;
    }
};

//============================================================================
// Version Hasher
//============================================================================

class VersionHasher {
public:
    // FNV-1a 64-bit hash
    static uint64_t Hash(const void* data, size_t size) {
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        uint64_t hash = 14695981039346656037ULL;  // FNV offset basis
        
        for (size_t i = 0; i < size; ++i) {
            hash ^= bytes[i];
            hash *= 1099511628211ULL;  // FNV prime
        }
        
        return hash;
    }
    
    // Hash string
    static uint64_t HashString(const std::string& str) {
        return Hash(str.data(), str.size());
    }
    
    // Hash multiple values
    template<typename... Args>
    static uint64_t HashValues(Args... args) {
        uint64_t hash = 14695981039346656037ULL;
        (HashValue(hash, args), ...);
        return hash;
    }
    
    template<typename T>
    static void HashValue(uint64_t& hash, const T& value) {
        hash ^= Hash(&value, sizeof(value));
        hash *= 1099511628211ULL;
    }
};

//============================================================================
// Execution Plan Registry
//============================================================================

class ExecutionPlanRegistry {
public:
    struct PlanEntry {
        ExecutionPlanVersion version;
        void* plan_data;
        size_t plan_size;
        uint64_t last_used;
        uint64_t use_count;
    };
    
    // Register a new plan
    void RegisterPlan(const ExecutionPlanVersion& version, void* plan_data, size_t plan_size) {
        PlanEntry entry;
        entry.version = version;
        entry.plan_data = plan_data;
        entry.plan_size = plan_size;
        entry.last_used = GetTimestamp();
        entry.use_count = 0;
        
        plans_[version] = entry;
    }
    
    // Find compatible plan
    PlanEntry* FindCompatiblePlan(const ExecutionPlanVersion& current_version) {
        for (auto& [version, entry] : plans_) {
            if (version.IsCompatibleWith(current_version)) {
                entry.last_used = GetTimestamp();
                entry.use_count++;
                return &entry;
            }
        }
        return nullptr;
    }
    
    // Invalidate plans that don't match current environment
    size_t InvalidateStalePlans(const ExecutionPlanVersion& current_version) {
        size_t invalidated = 0;
        
        for (auto it = plans_.begin(); it != plans_.end();) {
            if (!it->first.IsCompatibleWith(current_version)) {
                std::string diff = it->first.GetDifference(current_version);
                stale_plans_.push_back({it->first, diff, GetTimestamp()});
                
                // Free plan data
                // free(it->second.plan_data);
                
                it = plans_.erase(it);
                invalidated++;
            } else {
                ++it;
            }
        }
        
        return invalidated;
    }
    
    // Get plan statistics
    struct PlanStats {
        size_t active_plans;
        size_t stale_plans;
        size_t total_uses;
        uint64_t oldest_plan;
    };
    
    PlanStats GetStats() const {
        PlanStats stats;
        stats.active_plans = plans_.size();
        stats.stale_plans = stale_plans_.size();
        stats.total_uses = 0;
        stats.oldest_plan = UINT64_MAX;
        
        for (const auto& [version, entry] : plans_) {
            stats.total_uses += entry.use_count;
            stats.oldest_plan = std::min(stats.oldest_plan, entry.last_used);
        }
        
        return stats;
    }
    
    // Print plan status
    void PrintStatus() const {
        auto stats = GetStats();
        
        std::cout << "\n=== Execution Plan Registry ===\n";
        std::cout << "Active plans: " << stats.active_plans << "\n";
        std::cout << "Stale plans:  " << stats.stale_plans << "\n";
        std::cout << "Total uses:   " << stats.total_uses << "\n\n";
        
        if (!stale_plans_.empty()) {
            std::cout << "Recent invalidations:\n";
            for (const auto& stale : stale_plans_) {
                std::cout << "  - " << stale.reason << " at t=" << stale.timestamp << "\n";
            }
        }
    }

private:
    std::unordered_map<ExecutionPlanVersion, PlanEntry, 
                      std::hash<ExecutionPlanVersion>> plans_;
    
    struct StalePlan {
        ExecutionPlanVersion version;
        std::string reason;
        uint64_t timestamp;
    };
    std::vector<StalePlan> stale_plans_;
    
    uint64_t GetTimestamp() {
        static uint64_t counter = 0;
        return counter++;
    }
};

// Hash function for ExecutionPlanVersion
namespace std {
template<>
struct hash<RawrXD::NEVM::ExecutionPlanVersion> {
    size_t operator()(const RawrXD::NEVM::ExecutionPlanVersion& v) const {
        return static_cast<size_t>(RawrXD::NEVM::VersionHasher::HashValues(
            v.model_hash,
            v.tensor_layout_hash,
            v.kernel_registry_hash,
            v.precision_policy_hash,
            v.residency_policy_hash,
            v.math_mode_hash
        ));
    }
};
}

} // namespace NEVM
} // namespace RawrXD
