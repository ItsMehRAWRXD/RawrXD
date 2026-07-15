#include "sovereign/SelfOptimization.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include "sovereign/DistributedKV.hpp"
#include "sovereign/ExpertSharding.hpp"
#include "sovereign/GPUMesh.hpp"
#include <mutex>
#include <vector>
#include <map>
#include <algorithm>

namespace SelfOptimization {
    static std::mutex g_mutex;
    static DecisionCallback g_decisionCb;
    static std::vector<OptimizationDecision> g_pendingDecisions;
    static std::map<DecisionType, std::vector<float>> g_history;
    static SovereignTelemetry g_lastTelemetry{};
    static bool g_initialized = false;

    void Init() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = true;
        g_pendingDecisions.clear();
        g_history.clear();

        Beaconism::Emit(Beaconism::BEACON_SelfOptInit, {
            {"timestamp", Beaconism::GetTimestamp()}
        });
    }

    void Shutdown() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = false;
    }

    void Tick(const SovereignTelemetry& t) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_initialized) return;

        g_lastTelemetry = t;

        Beaconism::Emit(Beaconism::BEACON_SelfOptTick, {
            {"kv_pressure", t.kvCachePressure},
            {"moe_histogram_sum", t.moeHistogram[0] + t.moeHistogram[1] + t.moeHistogram[2]},
            {"gpu_timing_ms", t.gpuTimingMs},
            {"timestamp", Beaconism::GetTimestamp()}
        });

        if (t.kvCachePressure > 0.8f) {
            OptimizationDecision dec;
            dec.type = DecisionType::MIGRATE_TIER;
            dec.confidence = t.kvCachePressure;
            dec.expectedImprovement = t.kvCachePressure * 0.15f;
            dec.params = {{"action", "migrate_hot_to_warm"}, {"pressure", t.kvCachePressure}};
            dec.timestamp = Beaconism::GetTimestamp();
            g_pendingDecisions.push_back(dec);
        }

        float maxExpertLoad = *std::max_element(t.moeHistogram, t.moeHistogram + 8);
        float avgExpertLoad = 0;
        for (int i = 0; i < 8; i++) avgExpertLoad += t.moeHistogram[i];
        avgExpertLoad /= 8.0f;

        if (maxExpertLoad > avgExpertLoad * 2.0f) {
            OptimizationDecision dec;
            dec.type = DecisionType::REBALANCE_EXPERTS;
            dec.confidence = 0.7f;
            dec.expectedImprovement = (maxExpertLoad - avgExpertLoad) / maxExpertLoad * 0.2f;
            dec.params = {{"action", "rebalance_experts"}, {"max_load", maxExpertLoad}, {"avg_load", avgExpertLoad}};
            dec.timestamp = Beaconism::GetTimestamp();
            g_pendingDecisions.push_back(dec);
        }

        if (t.gpuTimingMs > 100.0f) {
            OptimizationDecision dec;
            dec.type = DecisionType::RESHARD_GPUS;
            dec.confidence = std::min(1.0f, t.gpuTimingMs / 200.0f);
            dec.expectedImprovement = (t.gpuTimingMs - 50.0f) / t.gpuTimingMs * 0.25f;
            dec.params = {{"action", "reshard_attention"}, {"gpu_timing_ms", t.gpuTimingMs}};
            dec.timestamp = Beaconism::GetTimestamp();
            g_pendingDecisions.push_back(dec);
        }
    }

    void LearnFromHistory() {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_initialized) return;

        Beaconism::Emit(Beaconism::BEACON_SelfOptLearn, {
            {"decision_history_size", g_pendingDecisions.size()},
            {"timestamp", Beaconism::GetTimestamp()}
        });

        for (const auto& dec : g_pendingDecisions) {
            g_history[dec.type].push_back(dec.expectedImprovement);
            if (g_history[dec.type].size() > 100) {
                g_history[dec.type].erase(g_history[dec.type].begin());
            }
        }
    }

    void ApplyOptimizations() {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_initialized) return;

        for (const auto& dec : g_pendingDecisions) {
            if (dec.confidence < 0.5f) continue;

            Beaconism::Emit(Beaconism::BEACON_SelfOptApply, {
                {"decision_type", static_cast<int>(dec.type)},
                {"confidence", dec.confidence},
                {"expected_improvement", dec.expectedImprovement}
            });

            switch (dec.type) {
                case DecisionType::MIGRATE_TIER:
                case DecisionType::REPLICATE_KV: {
                    DistributedKV::PublishKVState(
                        static_cast<uint64_t>(g_lastTelemetry.kvCachePressure * 1024 * 1024),
                        static_cast<uint64_t>((1.0f - g_lastTelemetry.kvCachePressure) * 512 * 1024),
                        0, 0
                    );
                    break;
                }
                case DecisionType::REBALANCE_EXPERTS: {
                    ExpertSharding::RebalanceExperts();
                    break;
                }
                case DecisionType::RESHARD_GPUS: {
                    auto devices = GPUMesh::GetActiveDevices();
                    if (!devices.empty()) {
                        GPUMesh::Init(devices);
                    }
                    break;
                }
                case DecisionType::ADJUST_ROUTING: {
                    nlohmann::json hint = {
                        {"type", "routing_hint"},
                        {"action", "adjust_weights"},
                        {"confidence", dec.confidence},
                        {"timestamp", Beaconism::GetTimestamp()}
                    };
                    Fabric::Instance().BroadcastJSON(hint);
                    break;
                }
            }

            if (g_decisionCb) g_decisionCb(dec);
        }

        g_pendingDecisions.clear();
    }

    void RegisterDecisionCallback(DecisionCallback cb) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_decisionCb = cb;
    }

    std::vector<OptimizationDecision> GetPendingDecisions() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_pendingDecisions;
    }

    void ClearDecisionHistory() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_pendingDecisions.clear();
        g_history.clear();
    }
}
