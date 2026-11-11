#include "quantum/ProbabilityEngine.hpp"
#include <mutex>
#include <random>
#include <cmath>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::mt19937 s_rng;
static size_t s_calculationCount = 0;

void ProbabilityEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_rng.seed(std::random_device{}());
        s_calculationCount = 0;
        s_initialized = true;
    }
}

void ProbabilityEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool ProbabilityEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

double ProbabilityEngine::CalculateProbability(const nlohmann::json& event) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return 0.0;
    
    s_calculationCount++;
    
    // Simple probability calculation based on event features
    double baseProb = event.value("base_probability", 0.5);
    double evidenceStrength = event.value("evidence_strength", 0.5);
    
    // Bayesian update
    double posterior = (baseProb * evidenceStrength) / 
                       (baseProb * evidenceStrength + (1 - baseProb) * (1 - evidenceStrength));
    
    return std::clamp(posterior, 0.0, 1.0);
}

nlohmann::json ProbabilityEngine::UpdateBelief(const nlohmann::json& prior, const nlohmann::json& evidence) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    double priorProb = prior.value("probability", 0.5);
    double likelihood = evidence.value("likelihood", 0.5);
    double evidenceProb = evidence.value("probability", 0.5);
    
    // Bayes' theorem: P(H|E) = P(E|H) * P(H) / P(E)
    double posteriorProb = (likelihood * priorProb) / std::max(evidenceProb, 0.001);
    
    return {
        {"probability", std::clamp(posteriorProb, 0.0, 1.0)},
        {"prior", priorProb},
        {"likelihood", likelihood},
        {"updated_at", std::chrono::system_clock::now().time_since_epoch().count()}
    };
}

nlohmann::json ProbabilityEngine::SampleDistribution(const nlohmann::json& distribution, int samples) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json::array();
    
    nlohmann::json results = nlohmann::json::array();
    
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    
    for (int i = 0; i < samples; ++i) {
        results.push_back({
            {"sample_id", i},
            {"value", dist(s_rng)},
            {"timestamp", std::chrono::system_clock::now().time_since_epoch().count()}
        });
    }
    
    return results;
}

double ProbabilityEngine::CalculateEntropy(const nlohmann::json& distribution) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return 0.0;
    
    double entropy = 0.0;
    
    if (distribution.is_array()) {
        for (const auto& prob : distribution) {
            if (prob.is_number()) {
                double p = prob.get<double>();
                if (p > 0) {
                    entropy -= p * std::log2(p);
                }
            }
        }
    }
    
    return entropy;
}

nlohmann::json ProbabilityEngine::CalculateConfidenceInterval(const nlohmann::json& estimate, double confidence) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    double mean = estimate.value("mean", 0.0);
    double stdDev = estimate.value("std_dev", 1.0);
    
    // For 95% confidence, z-score is approximately 1.96
    double zScore = (confidence == 0.95) ? 1.96 : 1.0;
    double margin = zScore * stdDev;
    
    return {
        {"confidence_level", confidence},
        {"mean", mean},
        {"lower_bound", mean - margin},
        {"upper_bound", mean + margin},
        {"margin_of_error", margin}
    };
}

nlohmann::json ProbabilityEngine::GetProbabilityMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"calculations_performed", s_calculationCount},
        {"engine_status", s_initialized ? "active" : "inactive"}
    };
}
