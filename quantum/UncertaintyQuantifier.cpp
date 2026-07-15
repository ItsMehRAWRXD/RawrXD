#include "quantum/UncertaintyQuantifier.hpp"
#include <mutex>
#include <vector>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::vector<nlohmann::json> s_uncertaintyHistory;
static size_t s_quantificationCount = 0;

void UncertaintyQuantifier::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_uncertaintyHistory.clear();
        s_quantificationCount = 0;
        s_initialized = true;
    }
}

void UncertaintyQuantifier::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool UncertaintyQuantifier::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json UncertaintyQuantifier::QuantifyUncertainty(const nlohmann::json& prediction) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    s_quantificationCount++;
    
    double confidence = prediction.value("confidence", 0.5);
    double variance = prediction.value("variance", 0.25);
    
    // Calculate uncertainty metrics
    double uncertainty = 1.0 - confidence;
    double standardDeviation = std::sqrt(variance);
    
    nlohmann::json result = {
        {"prediction", prediction},
        {"uncertainty", uncertainty},
        {"confidence", confidence},
        {"variance", variance},
        {"std_dev", standardDeviation},
        {"reliability", confidence > 0.7 ? "high" : (confidence > 0.4 ? "medium" : "low")},
        {"quantified_at", std::chrono::system_clock::now().time_since_epoch().count()}
    };
    
    s_uncertaintyHistory.push_back(result);
    if (s_uncertaintyHistory.size() > 1000) {
        s_uncertaintyHistory.erase(s_uncertaintyHistory.begin());
    }
    
    return result;
}

nlohmann::json UncertaintyQuantifier::PropagateUncertainty(const nlohmann::json& inputs) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    // Calculate combined uncertainty from multiple inputs
    double totalVariance = 0.0;
    double totalWeight = 0.0;
    
    if (inputs.is_array()) {
        for (const auto& input : inputs) {
            double variance = input.value("variance", 0.0);
            double weight = input.value("weight", 1.0);
            totalVariance += variance * weight * weight;
            totalWeight += weight;
        }
    }
    
    double combinedStdDev = totalWeight > 0 ? std::sqrt(totalVariance) / totalWeight : 0.0;
    
    return {
        {"propagated_variance", totalVariance},
        {"propagated_std_dev", combinedStdDev},
        {"input_count", inputs.size()},
        {"propagated_at", std::chrono::system_clock::now().time_since_epoch().count()}
    };
}

nlohmann::json UncertaintyQuantifier::ReduceUncertainty(const nlohmann::json& uncertainEstimate, const nlohmann::json& newEvidence) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    double priorVariance = uncertainEstimate.value("variance", 0.25);
    double evidencePrecision = newEvidence.value("precision", 1.0);
    
    // Bayesian variance reduction
    double posteriorVariance = 1.0 / (1.0 / priorVariance + evidencePrecision);
    
    return {
        {"prior_variance", priorVariance},
        {"posterior_variance", posteriorVariance},
        {"variance_reduction", priorVariance - posteriorVariance},
        {"reduction_percentage", (priorVariance - posteriorVariance) / priorVariance * 100.0},
        {"updated_at", std::chrono::system_clock::now().time_since_epoch().count()}
    };
}

nlohmann::json UncertaintyQuantifier::GetUncertaintyMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    double avgUncertainty = 0.0;
    for (const auto& record : s_uncertaintyHistory) {
        avgUncertainty += record.value("uncertainty", 0.0);
    }
    
    size_t count = s_uncertaintyHistory.size();
    
    return {
        {"quantifications_performed", s_quantificationCount},
        {"history_entries", count},
        {"avg_uncertainty", count > 0 ? avgUncertainty / count : 0.0},
        {"current_status", s_initialized ? "active" : "inactive"}
    };
}
