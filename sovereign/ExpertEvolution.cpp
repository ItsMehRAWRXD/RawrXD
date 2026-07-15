#include "sovereign/ExpertEvolution.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include "sovereign/ExpertSharding.hpp"
#include <mutex>
#include <algorithm>
#include <numeric>

namespace ExpertEvolution {
    static std::mutex g_mutex;
    static std::map<uint64_t, ExpertProfile> g_profiles;
    static EvolutionCallback g_evolutionCb;
    static ProfileCallback g_profileCb;
    static bool g_initialized = false;

    void Init() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = true;

        Fabric::Instance().RegisterHandler("expert_mutation", OnFabricMessage);
        Fabric::Instance().RegisterHandler("expert_profile_sync", OnFabricMessage);

        Beaconism::Emit(Beaconism::BEACON_ExpertEvolutionInit, {{"timestamp", Beaconism::GetTimestamp()}});
    }

    void Shutdown() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = false;
    }

    void RecordExpertActivation(uint64_t expertId, float latency, bool success) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto& profile = g_profiles[expertId];
        profile.id = expertId;
        profile.activationFrequency += 1.0f;
        profile.avgLatency = (profile.avgLatency * 0.9f) + (latency * 0.1f);
        profile.accuracy = (profile.accuracy * 0.95f) + (success ? 1.0f : 0.0f) * 0.05f;

        if (g_profileCb) g_profileCb(profile);
    }

    void UpdateExpertLoad(uint64_t expertId, float load) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto& profile = g_profiles[expertId];
        profile.id = expertId;
        profile.loadHistory.push_back(load);
        if (profile.loadHistory.size() > 100) {
            profile.loadHistory.erase(profile.loadHistory.begin());
        }
    }

    MutationDecision EvaluateMutation(uint64_t expertId) {
        std::lock_guard<std::mutex> lock(g_mutex);
        MutationDecision decision;
        decision.expertId = expertId;
        decision.mutation = ExpertMutation::NONE;
        decision.confidence = 0.0f;
        decision.timestamp = Beaconism::GetTimestamp();

        auto it = g_profiles.find(expertId);
        if (it == g_profiles.end()) return decision;

        const auto& profile = it->second;

        if (profile.loadHistory.size() >= 10) {
            float avgLoad = std::accumulate(profile.loadHistory.begin(), profile.loadHistory.end(), 0.0f) / profile.loadHistory.size();
            float maxLoad = *std::max_element(profile.loadHistory.begin(), profile.loadHistory.end());

            if (maxLoad > 0.9f && avgLoad > 0.7f) {
                decision.mutation = ExpertMutation::SPLIT;
                decision.confidence = avgLoad;
                decision.rationale = "High sustained load - splitting expert";
            } else if (avgLoad < 0.1f && profile.activationFrequency > 100) {
                decision.mutation = ExpertMutation::PRUNE;
                decision.confidence = 1.0f - avgLoad;
                decision.rationale = "Low utilization - pruning candidate";
            } else if (profile.accuracy > 0.95f && avgLoad > 0.5f) {
                decision.mutation = ExpertMutation::SPECIALIZE;
                decision.confidence = profile.accuracy;
                decision.rationale = "High accuracy with load - specializing";
            }
        }

        return decision;
    }

    void ApplyMutation(const MutationDecision& decision) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_initialized) return;

        auto it = g_profiles.find(decision.expertId);
        if (it != g_profiles.end()) {
            it->second.generation++;
            it->second.lastMutation = decision.timestamp;
        }

        nlohmann::json msg = {
            {"type", "expert_mutation"},
            {"expert_id", decision.expertId},
            {"mutation", static_cast<int>(decision.mutation)},
            {"confidence", decision.confidence},
            {"rationale", decision.rationale},
            {"timestamp", decision.timestamp}
        };
        Fabric::Instance().BroadcastJSON(msg);

        if (g_evolutionCb) g_evolutionCb(decision);

        Beaconism::Emit(Beaconism::BEACON_ExpertMutation, {
            {"expert_id", decision.expertId},
            {"mutation", static_cast<int>(decision.mutation)},
            {"confidence", decision.confidence}
        });
    }

    std::vector<ExpertProfile> GetExpertProfiles() {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::vector<ExpertProfile> result;
        for (const auto& [id, profile] : g_profiles) {
            result.push_back(profile);
        }
        return result;
    }

    ExpertProfile GetProfile(uint64_t expertId) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_profiles.find(expertId);
        return (it != g_profiles.end()) ? it->second : ExpertProfile{};
    }

    void RegisterEvolutionCallback(EvolutionCallback cb) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_evolutionCb = cb;
    }

    void RegisterProfileCallback(ProfileCallback cb) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_profileCb = cb;
    }

    void EvolveFromTelemetry(const SovereignTelemetry& t) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_initialized) return;

        for (int i = 0; i < 8; i++) {
            uint64_t expertId = i;
            UpdateExpertLoad(expertId, t.moeHistogram[i]);

            if (t.moeHistogram[i] > 0) {
                RecordExpertActivation(expertId, t.gpuTimingMs / 8.0f, t.kvCachePressure < 0.9f);
            }

            auto decision = EvaluateMutation(expertId);
            if (decision.confidence > 0.7f) {
                ApplyMutation(decision);
            }
        }

        nlohmann::json syncMsg = {
            {"type", "expert_profile_sync"},
            {"profiles", g_profiles},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(syncMsg);
    }

    void OnFabricMessage(const nlohmann::json& msg) {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::string type = msg.value("type", "");

        if (type == "expert_mutation") {
            uint64_t expertId = msg.value("expert_id", 0ULL);
            ExpertMutation mutation = static_cast<ExpertMutation>(msg.value("mutation", 0));
            float confidence = msg.value("confidence", 0.0f);

            Beaconism::Emit(Beaconism::BEACON_ExpertMutationRemote, {
                {"expert_id", expertId},
                {"mutation", static_cast<int>(mutation)},
                {"confidence", confidence}
            });
        }
        else if (type == "expert_profile_sync") {
            auto profiles = msg.value("profiles", nlohmann::json::object());
            for (auto& [id, profileJson] : profiles.items()) {
                uint64_t expertId = std::stoull(id);
                if (g_profiles.find(expertId) == g_profiles.end()) {
                    ExpertProfile profile;
                    profile.id = expertId;
                    profile.specialization = profileJson.value("specialization", "unknown");
                    profile.generation = profileJson.value("generation", 0);
                    g_profiles[expertId] = profile;
                }
            }
        }
    }
}
