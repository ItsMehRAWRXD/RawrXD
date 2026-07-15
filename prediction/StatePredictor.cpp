#include "prediction/StatePredictor.hpp"
#include "temporal/TemporalMemory.hpp"
#include <mutex>
#include <cmath>

static std::mutex s_mutex;
static bool s_initialized = false;
static double predictionAccuracy = 0.8; // Initial confidence
static int totalPredictions = 0;
static int correctPredictions = 0;

void StatePredictor::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        predictionAccuracy = 0.8;
        totalPredictions = 0;
        correctPredictions = 0;
        s_initialized = true;
    }
}

void StatePredictor::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    // Periodic model refinement
}

bool StatePredictor::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json StatePredictor::PredictNextState(const nlohmann::json& currentState, int steps) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    // Simple prediction: extrapolate from temporal patterns
    auto timeline = TemporalMemory::GetTimeline();
    
    nlohmann::json prediction = currentState;
    prediction["predicted"] = true;
    prediction["prediction_steps"] = steps;
    prediction["confidence"] = predictionAccuracy * std::pow(0.9, steps - 1);
    
    // If we have history, project forward
    if (timeline.size() >= 2) {
        auto last = timeline.back();
        auto prev = timeline[timeline.size() - 2];
        
        // Detect trend and project
        if (last.contains("continuity_score") && prev.contains("continuity_score")) {
            double trend = last["continuity_score"].get<double>() - 
                          prev["continuity_score"].get<double>();
            double projected = last["continuity_score"].get<double>() + (trend * steps);
            prediction["projected_continuity"] = std::max(0.0, std::min(1.0, projected));
        }
    }
    
    return prediction;
}

nlohmann::json StatePredictor::PredictTrajectory(const nlohmann::json& initialState, int horizon) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json::array();
    
    nlohmann::json trajectory = nlohmann::json::array();
    nlohmann::json current = initialState;
    
    for (int i = 1; i <= horizon; ++i) {
        current = PredictNextState(current, i);
        trajectory.push_back(current);
    }
    
    return trajectory;
}

double StatePredictor::GetPredictionConfidence() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return predictionAccuracy;
}

void StatePredictor::UpdateModel(const nlohmann::json& actual, const nlohmann::json& predicted) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    totalPredictions++;
    
    // Simple accuracy update
    bool match = (actual == predicted);
    if (match) {
        correctPredictions++;
    }
    
    // Update accuracy with exponential moving average
    predictionAccuracy = 0.95 * predictionAccuracy + 0.05 * (match ? 1.0 : 0.0);
}

nlohmann::json StatePredictor::GetModelMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"accuracy", predictionAccuracy},
        {"total_predictions", totalPredictions},
        {"correct_predictions", correctPredictions},
        {"accuracy_rate", totalPredictions > 0 ? (double)correctPredictions / totalPredictions : 0.0}
    };
}
