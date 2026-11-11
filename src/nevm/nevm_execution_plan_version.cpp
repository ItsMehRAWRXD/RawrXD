//============================================================================
// nevm_execution_plan_version.cpp
// RawrXD N-EVM - Execution Plan Version Implementation
//============================================================================

#include "nevm_execution_plan_version.hpp"
#include <iostream>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Execution Plan Version
//============================================================================

ExecutionPlanVersion::ExecutionPlanVersion() {
    // Initialize with zeros
    model_hash = "0";
    tensor_layout_hash = "0";
    kernel_registry_hash = "0";
    precision_policy_hash = "0";
    residency_policy_hash = "0";
    math_mode_hash = "0";
    timestamp = 0;
}

bool ExecutionPlanVersion::IsCompatibleWith(const ExecutionPlanVersion& other) const {
    // All six hashes must match for compatibility
    return model_hash == other.model_hash &&
           tensor_layout_hash == other.tensor_layout_hash &&
           kernel_registry_hash == other.kernel_registry_hash &&
           precision_policy_hash == other.precision_policy_hash &&
           residency_policy_hash == other.residency_policy_hash &&
           math_mode_hash == other.math_mode_hash;
}

std::string ExecutionPlanVersion::ToString() const {
    return model_hash.substr(0, 8) + ":" +
           tensor_layout_hash.substr(0, 8) + ":" +
           kernel_registry_hash.substr(0, 8);
}

Json::Value ExecutionPlanVersion::ToJSON() const {
    Json::Value json;
    json["model_hash"] = model_hash;
    json["tensor_layout_hash"] = tensor_layout_hash;
    json["kernel_registry_hash"] = kernel_registry_hash;
    json["precision_policy_hash"] = precision_policy_hash;
    json["residency_policy_hash"] = residency_policy_hash;
    json["math_mode_hash"] = math_mode_hash;
    json["timestamp"] = static_cast<Json::UInt64>(timestamp);
    return json;
}

ExecutionPlanVersion ExecutionPlanVersion::FromJSON(const Json::Value& json) {
    ExecutionPlanVersion version;
    version.model_hash = json.get("model_hash", "0").asString();
    version.tensor_layout_hash = json.get("tensor_layout_hash", "0").asString();
    version.kernel_registry_hash = json.get("kernel_registry_hash", "0").asString();
    version.precision_policy_hash = json.get("precision_policy_hash", "0").asString();
    version.residency_policy_hash = json.get("residency_policy_hash", "0").asString();
    version.math_mode_hash = json.get("math_mode_hash", "0").asString();
    version.timestamp = json.get("timestamp", 0).asUInt64();
    return version;
}

//============================================================================
// Execution Plan Registry
//============================================================================

void ExecutionPlanRegistry::RegisterPlan(const std::string& plan_id,
                                         const ExecutionPlanVersion& version) {
    plans_[plan_id] = version;
}

bool ExecutionPlanRegistry::IsPlanValid(const std::string& plan_id,
                                        const ExecutionPlanVersion& current) const {
    auto it = plans_.find(plan_id);
    if (it == plans_.end()) {
        return false;  // Plan not found
    }
    
    return it->second.IsCompatibleWith(current);
}

void ExecutionPlanRegistry::InvalidateStalePlans(const ExecutionPlanVersion& current) {
    std::vector<std::string> to_remove;
    
    for (const auto& [id, version] : plans_) {
        if (!version.IsCompatibleWith(current)) {
            to_remove.push_back(id);
        }
    }
    
    for (const auto& id : to_remove) {
        plans_.erase(id);
        std::cout << "Invalidated stale plan: " << id << "\n";
    }
}

ExecutionPlanVersion ExecutionPlanRegistry::GetPlanVersion(const std::string& plan_id) const {
    auto it = plans_.find(plan_id);
    if (it != plans_.end()) {
        return it->second;
    }
    return ExecutionPlanVersion();
}

void ExecutionPlanRegistry::Clear() {
    plans_.clear();
}

size_t ExecutionPlanRegistry::GetPlanCount() const {
    return plans_.size();
}

} // namespace NEVM
} // namespace RawrXD
