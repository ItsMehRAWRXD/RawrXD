#include "sovereign/RoutingHeuristicsEngine.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include "sovereign/GlobalAttentionRouter.hpp"
#include <mutex>
#include <chrono>
#include <algorithm>

namespace RoutingHeuristics {
    static std::mutex g_mutex;
    static HeuristicModel g_model;
    static RoutingStrategy g_currentStrategy = RoutingStrategy::HYBRID_ML;
    static PredictionCallback g_predictionCb;
    static std::map<std::string, std::vector<float>> g_latencyHistory;
    static bool g_initialized = false;

    void Init() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_model.learningRate = 0.01f;
        g_model.version = 1;
        g_initialized = true;

        Fabric::Instance().RegisterHandler("routing_model_sync", OnFabricMessage);
        Fabric::Instance().RegisterHandler("routing_prediction", OnFabricMessage);

        Beaconism::Emit(Beaconism::BEACON_RoutingHeuristicsInit, {
            {"strategy", static_cast<int>(g_currentStrategy)},
            {"version", g_model.version}
        });
    }

    void Shutdown() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = false;
    }

    RoutePrediction PredictRoute(const std::string& destinationHint, size_t dataSize) {
        std::lock_guard<std::mutex> lock(g_mutex);
        RoutePrediction pred;
        pred.timestamp = Beaconism::GetTimestamp();
        pred.strategy = g_currentStrategy;

        auto nodes = GlobalAttentionRouter::GetClusterNodes();
        if (nodes.empty()) {
            pred.targetNode = Fabric::Instance().GetNodeId();
            pred.confidence = 0.5f;
            return pred;
        }

        float bestScore = -1.0f;
        for (const auto& node : nodes) {
            float latency = g_model.latencyHistory.count(node) ? g_model.latencyHistory[node] : 100.0f;
            float weight = g_model.nodeWeights.count(node) ? g_model.nodeWeights[node] : 1.0f;
            float load = 1.0f / (weight + 0.001f);

            float score = 0.0f;
            switch (g_currentStrategy) {
                case RoutingStrategy::LATENCY_MIN:
                    score = 1.0f / (latency + 1.0f);
                    break;
                case RoutingStrategy::LOAD_BALANCE:
                    score = 1.0f / (load + 0.1f);
                    break;
                case RoutingStrategy::THROUGHPUT_MAX:
                    score = weight * (1.0f / (latency + 1.0f));
                    break;
                case RoutingStrategy::COST_MIN:
                    score = 1.0f / (latency * load + 1.0f);
                    break;
                case RoutingStrategy::HYBRID_ML:
                    score = (weight * 0.4f) + (1.0f / (latency + 1.0f) * 0.3f) + (1.0f / (load + 0.1f) * 0.3f);
                    break;
            }

            if (score > bestScore) {
                bestScore = score;
                pred.targetNode = node;
                pred.predictedLatency = latency;
                pred.loadScore = load;
            }
        }

        pred.confidence = std::min(1.0f, bestScore);

        nlohmann::json msg = {
            {"type", "routing_prediction"},
            {"target", pred.targetNode},
            {"strategy", static_cast<int>(pred.strategy)},
            {"confidence", pred.confidence},
            {"timestamp", pred.timestamp}
        };
        Fabric::Instance().BroadcastJSON(msg);

        if (g_predictionCb) g_predictionCb(pred);

        Beaconism::Emit(Beaconism::BEACON_RoutingPrediction, {
            {"target", pred.targetNode},
            {"strategy", static_cast<int>(pred.strategy)},
            {"confidence", pred.confidence}
        });

        return pred;
    }

    void UpdateModel(const std::string& nodeId, float actualLatency, bool success) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_initialized) return;

        g_latencyHistory[nodeId].push_back(actualLatency);
        if (g_latencyHistory[nodeId].size() > 100) {
            g_latencyHistory[nodeId].erase(g_latencyHistory[nodeId].begin());
        }

        float avgLatency = 0.0f;
        for (float lat : g_latencyHistory[nodeId]) avgLatency += lat;
        avgLatency /= g_latencyHistory[nodeId].size();

        g_model.latencyHistory[nodeId] = avgLatency;

        float error = actualLatency - (g_model.latencyHistory.count(nodeId) ? g_model.latencyHistory[nodeId] : actualLatency);
        g_model.nodeWeights[nodeId] += g_model.learningRate * error * (success ? 1.0f : -0.5f);
        g_model.nodeWeights[nodeId] = std::max(0.1f, std::min(10.0f, g_model.nodeWeights[nodeId]));

        Beaconism::Emit(Beaconism::BEACON_RoutingModelUpdate, {
            {"node", nodeId},
            {"latency", actualLatency},
            {"weight", g_model.nodeWeights[nodeId]}
        });
    }

    void TrainFromTelemetry(const SovereignTelemetry& t) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_initialized) return;

        auto nodes = GlobalAttentionRouter::GetClusterNodes();
        for (const auto& node : nodes) {
            UpdateModel(node, t.gpuTimingMs / std::max(1.0f, t.kvCachePressure * 10.0f), t.kvCachePressure < 0.9f);
        }

        g_model.version++;

        nlohmann::json msg = {
            {"type", "routing_model_sync"},
            {"version", g_model.version},
            {"weights", g_model.nodeWeights},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);
    }

    void SetStrategy(RoutingStrategy strategy) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_currentStrategy = strategy;
        Beaconism::Emit(Beaconism::BEACON_RoutingStrategyChange, {{"strategy", static_cast<int>(strategy)}});
    }

    RoutingStrategy GetCurrentStrategy() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_currentStrategy;
    }

    void RegisterPredictionCallback(PredictionCallback cb) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_predictionCb = cb;
    }

    HeuristicModel ExportModel() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_model;
    }

    void ImportModel(const HeuristicModel& model) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_model = model;
    }

    void OnFabricMessage(const nlohmann::json& msg) {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::string type = msg.value("type", "");

        if (type == "routing_model_sync") {
            uint32_t version = msg.value("version", 0);
            if (version > g_model.version) {
                g_model.version = version;
                auto weights = msg.value("weights", nlohmann::json::object());
                for (auto& [node, weight] : weights.items()) {
                    g_model.nodeWeights[node] = weight.get<float>();
                }
            }
        }
    }

    bool RoutingHeuristicsEngine::IsReady() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_initialized;
    }

    // Alias for audit compatibility
    RoutePrediction RoutingHeuristicsEngine::Predict(const std::string& destinationHint, size_t dataSize) {
        return PredictRoute(destinationHint, dataSize);
    }
}
