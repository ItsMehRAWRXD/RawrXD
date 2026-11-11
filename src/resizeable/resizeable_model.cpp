// ============================================================================
// resizeable_model.cpp — Dynamic Subnetwork Activation Implementation
// ============================================================================

#include "resizeable_model.h"
#include <sstream>
#include <iostream>
#include <algorithm>

namespace rawrxd {
namespace resizeable {

// ============================================================================
// Constructor
// ============================================================================
ResizeableModel::ResizeableModel() = default;

// ============================================================================
// Initialization
// ============================================================================
void ResizeableModel::Initialize(uint64_t total_params, uint64_t memory_budget_bytes) {
    m_totalParams = total_params;
    m_memoryBudget = memory_budget_bytes;
    m_step = 0;
}

void ResizeableModel::AddGroup(const WeightGroup& group) {
    m_groups.push_back(group);
}

void ResizeableModel::SetTaskProfiles(const std::vector<TaskProfile>& profiles) {
    m_profiles = profiles;
}

// ============================================================================
// Expert Selection
// ============================================================================
std::vector<std::string> ResizeableModel::SelectByProfile(const TaskProfile& profile) {
    std::vector<std::string> selected;

    // Add main attractions
    for (const auto& name : profile.main_attractions) {
        auto* group = FindGroupMutable(name);
        if (group) {
            selected.push_back(name);
            group->activation_score = 1.0f;
        }
    }

    // Add supporting groups
    for (const auto& name : profile.supporting) {
        auto* group = FindGroupMutable(name);
        if (group) {
            selected.push_back(name);
            group->activation_score = 0.5f;
        }
    }

    return selected;
}

std::vector<std::string> ResizeableModel::SelectExperts(const std::string& task_type) {
    // Find matching profile
    for (const auto& profile : m_profiles) {
        if (profile.task_type == task_type) {
            return SelectByProfile(profile);
        }
    }

    // Fallback: activate all groups with usage > threshold
    std::vector<std::string> selected;
    for (auto& group : m_groups) {
        if (group.usage_score > m_activationThreshold) {
            selected.push_back(group.name);
            group.activation_score = group.usage_score;
        }
    }
    return selected;
}

// ============================================================================
// Record Inference
// ============================================================================
void ResizeableModel::RecordInference(const std::vector<std::string>& activated_groups) {
    m_step++;

    for (auto& group : m_groups) {
        bool was_used = std::find(activated_groups.begin(), activated_groups.end(),
                                   group.name) != activated_groups.end();
        if (was_used) {
            group.use_count++;
            group.last_used_step = m_step;
            group.usage_score = std::min(1.0f, group.usage_score + 0.1f);
            group.state = WeightState::Active;
        }
    }
}

// ============================================================================
// Decay — unused groups lose weight over time
// ============================================================================
void ResizeableModel::StepDecay() {
    for (auto& group : m_groups) {
        // Decay usage score
        group.usage_score *= m_decayFactor;

        // If usage drops below threshold, start cooling
        if (group.usage_score < m_activationThreshold && group.state == WeightState::Active) {
            group.state = WeightState::Cooling;
            group.activation_score = group.usage_score;
        }

        // If cooling for too long, mark for eviction
        if (group.state == WeightState::Cooling && group.usage_score < m_activationThreshold * 0.5f) {
            group.state = WeightState::Evicting;
            group.activation_score = 0.0f;
        }
    }

    // Enforce budget after decay
    EnforceBudget();
}

// ============================================================================
// Budget Enforcement
// ============================================================================
bool ResizeableModel::EnforceBudget() {
    if (m_memoryBudget == 0) return true;

    while (CurrentMemoryUsage() > m_memoryBudget) {
        // Find lowest-scored active group to evict
        auto* lowest = &m_groups[0];
        for (auto& group : m_groups) {
            if (group.state == WeightState::Active || group.state == WeightState::Cooling) {
                if (group.usage_score < lowest->usage_score) {
                    lowest = &group;
                }
            }
        }

        if (lowest->state == WeightState::Active || lowest->state == WeightState::Cooling) {
            DeactivateGroup(lowest->name);
        } else {
            break; // Nothing left to evict
        }
    }

    return CurrentMemoryUsage() <= m_memoryBudget;
}

// ============================================================================
// Group Activation/Deactivation
// ============================================================================
void ResizeableModel::ActivateGroup(const std::string& name) {
    auto* group = FindGroupMutable(name);
    if (!group) return;

    if (group->state == WeightState::Dormant || group->state == WeightState::Evicting) {
        group->state = WeightState::Loading;
        if (m_loadCb) {
            m_loadCb(name);
        }
        group->state = WeightState::Active;
        group->location = DeviceLocation::VRAM;
    }
}

void ResizeableModel::DeactivateGroup(const std::string& name) {
    auto* group = FindGroupMutable(name);
    if (!group) return;

    if (group->state == WeightState::Active || group->state == WeightState::Cooling) {
        group->state = WeightState::Evicting;
        if (m_unloadCb) {
            m_unloadCb(name);
        }
        group->state = WeightState::Dormant;
        group->location = DeviceLocation::None;
        group->activation_score = 0.0f;
        group->usage_score = 0.0f;
    }
}

// ============================================================================
// Statistics
// ============================================================================
size_t ResizeableModel::ActiveGroupCount() const {
    size_t count = 0;
    for (const auto& g : m_groups) {
        if (g.state == WeightState::Active) count++;
    }
    return count;
}

uint64_t ResizeableModel::WeightedParams() const {
    uint64_t total = 0;
    for (const auto& g : m_groups) {
        if (g.state == WeightState::Active) {
            total += g.parameter_count;
        }
    }
    return total;
}

double ResizeableModel::MemorySavedFraction() const {
    if (m_totalParams == 0) return 0.0;
    uint64_t weighted = WeightedParams();
    return 1.0 - (double)weighted / (double)m_totalParams;
}

uint64_t ResizeableModel::CurrentMemoryUsage() const {
    uint64_t total = 0;
    for (const auto& g : m_groups) {
        if (g.state == WeightState::Active || g.state == WeightState::Loading) {
            total += g.memory_bytes;
        }
    }
    return total;
}

// ============================================================================
// Find Group
// ============================================================================
const WeightGroup* ResizeableModel::FindGroup(const std::string& name) const {
    for (const auto& g : m_groups) {
        if (g.name == name) return &g;
    }
    return nullptr;
}

WeightGroup* ResizeableModel::FindGroupMutable(const std::string& name) {
    for (auto& g : m_groups) {
        if (g.name == name) return &g;
    }
    return nullptr;
}

// ============================================================================
// Serialization
// ============================================================================
std::string ResizeableModel::ToJSON() const {
    std::ostringstream os;
    os << "{\n";
    os << "  \"total_params\": " << m_totalParams << ",\n";
    os << "  \"memory_budget\": " << m_memoryBudget << ",\n";
    os << "  \"step\": " << m_step << ",\n";
    os << "  \"groups\": [\n";
    for (size_t i = 0; i < m_groups.size(); ++i) {
        const auto& g = m_groups[i];
        os << "    {\n";
        os << "      \"name\": \"" << g.name << "\",\n";
        os << "      \"type\": \"" << g.type << "\",\n";
        os << "      \"state\": " << (int)g.state << ",\n";
        os << "      \"params\": " << g.parameter_count << ",\n";
        os << "      \"usage\": " << g.usage_score << ",\n";
        os << "      \"magnitude\": " << g.magnitude << ",\n";
        os << "      \"use_count\": " << g.use_count << "\n";
        os << "    }";
        if (i < m_groups.size() - 1) os << ",";
        os << "\n";
    }
    os << "  ]\n";
    os << "}\n";
    return os.str();
}

bool ResizeableModel::FromJSON(const std::string& json) {
    // Simple JSON parser for state restoration
    // In production, use nlohmann::json
    (void)json;
    return true;
}

} // namespace resizeable
} // namespace rawrxd
