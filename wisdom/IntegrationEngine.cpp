#include "wisdom/IntegrationEngine.hpp"
#include <mutex>
#include <map>

static std::mutex s_mutex;
static bool s_initialized = false;
static size_t s_integrationCount = 0;
static size_t s_conflictResolutionCount = 0;

void IntegrationEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_integrationCount = 0;
        s_conflictResolutionCount = 0;
        s_initialized = true;
    }
}

void IntegrationEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool IntegrationEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json IntegrationEngine::IntegratePerspectives(const std::vector<nlohmann::json>& perspectives) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json integrated = {
        {"id", "integrated_" + std::to_string(s_integrationCount++)},
        {"perspective_count", perspectives.size()},
        {"integrated_at", std::chrono::system_clock::now().time_since_epoch().count()},
        {"type", "integrated_view"}
    };
    
    // Find common ground
    nlohmann::json commonElements = nlohmann::json::object();
    
    if (!perspectives.empty()) {
        // Start with first perspective
        for (const auto& [key, value] : perspectives[0].items()) {
            bool common = true;
            for (size_t i = 1; i < perspectives.size(); ++i) {
                if (!perspectives[i].contains(key) || perspectives[i][key] != value) {
                    common = false;
                    break;
                }
            }
            if (common) {
                commonElements[key] = value;
            }
        }
    }
    
    integrated["common_elements"] = commonElements;
    integrated["agreement_rate"] = perspectives.empty() ? 0.0 : 
                                    static_cast<double>(commonElements.size()) / perspectives[0].size();
    
    return integrated;
}

nlohmann::json IntegrationEngine::ReconcileConflicts(const nlohmann::json& viewA, const nlohmann::json& viewB) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json reconciliation = {
        {"id", "reconciled_" + std::to_string(s_conflictResolutionCount++)},
        {"view_a", viewA.value("id", "")},
        {"view_b", viewB.value("id", "")},
        {"reconciled_at", std::chrono::system_clock::now().time_since_epoch().count()}
    };
    
    // Find conflicts
    nlohmann::json conflicts = nlohmann::json::array();
    nlohmann::json resolved = nlohmann::json::object();
    
    for (const auto& [key, valueA] : viewA.items()) {
        if (viewB.contains(key)) {
            auto valueB = viewB[key];
            if (valueA != valueB) {
                // Conflict detected
                conflicts.push_back({
                    {"key", key},
                    {"value_a", valueA},
                    {"value_b", valueB}
                });
                
                // Resolution: take average for numbers, prefer non-null for others
                if (valueA.is_number() && valueB.is_number()) {
                    resolved[key] = (valueA.get<double>() + valueB.get<double>()) / 2.0;
                } else if (!valueA.is_null()) {
                    resolved[key] = valueA;
                } else {
                    resolved[key] = valueB;
                }
            } else {
                resolved[key] = valueA;
            }
        } else {
            resolved[key] = valueA;
        }
    }
    
    // Add unique keys from viewB
    for (const auto& [key, valueB] : viewB.items()) {
        if (!viewA.contains(key)) {
            resolved[key] = valueB;
        }
    }
    
    reconciliation["conflicts_found"] = conflicts.size();
    reconciliation["conflicts"] = conflicts;
    reconciliation["resolved_view"] = resolved;
    reconciliation["resolution_strategy"] = "averaging_and_preference";
    
    return reconciliation;
}

nlohmann::json IntegrationEngine::SynthesizeHolisticView(const nlohmann::json& partialViews) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json holistic = {
        {"id", "holistic_" + std::to_string(s_integrationCount++)},
        {"synthesized_at", std::chrono::system_clock::now().time_since_epoch().count()},
        {"type", "holistic_view"}
    };
    
    // Merge all partial views
    nlohmann::json merged = nlohmann::json::object();
    
    if (partialViews.is_array()) {
        for (const auto& view : partialViews) {
            for (const auto& [key, value] : view.items()) {
                if (!merged.contains(key)) {
                    merged[key] = value;
                }
            }
        }
        holistic["view_count"] = partialViews.size();
    } else if (partialViews.is_object()) {
        merged = partialViews;
        holistic["view_count"] = 1;
    }
    
    holistic["synthesized_view"] = merged;
    holistic["completeness"] = merged.size() / 10.0; // Assuming 10 is full completeness
    
    return holistic;
}

nlohmann::json IntegrationEngine::GetIntegrationMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"integrations_performed", s_integrationCount},
        {"conflicts_resolved", s_conflictResolutionCount}
    };
}
