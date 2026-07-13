#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace TranscendentUnity {

// Forward declarations
struct TranscendentUnityStructure;
struct UnityTranscendent;
struct HarmonyTranscendent;
struct BalanceTranscendent;
struct SynthesisTranscendent;

// Core data structures
struct TranscendentUnityStructure {
    std::string transcendentId;
    std::string name;
    float transcendence;   // 0.0 to 1.0
    float unity;         // 0.0 to 1.0
    float harmony;       // 0.0 to 1.0
    float balance;       // 0.0 to 1.0
    float synthesis;     // 0.0 to 1.0
    int64_t createdAt;
    int64_t lastModified;
    bool isActive;
    
    nlohmann::json ToJson() const;
    static TranscendentUnityStructure FromJson(const nlohmann::json& j);
};

struct UnityTranscendent {
    std::string unityId;
    std::string name;
    float unity;         // 0.0 to 1.0
    float transcendence; // 0.0 to 1.0
    float cohesion;    // 0.0 to 1.0
    float oneness;     // 0.0 to 1.0
    bool isUnified;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static UnityTranscendent FromJson(const nlohmann::json& j);
};

struct HarmonyTranscendent {
    std::string harmonyId;
    std::string name;
    float harmony;       // 0.0 to 1.0
    float transcendence; // 0.0 to 1.0
    float resonance;   // 0.0 to 1.0
    float alignment;   // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static HarmonyTranscendent FromJson(const nlohmann::json& j);
};

struct BalanceTranscendent {
    std::string balanceId;
    std::string name;
    float balance;       // 0.0 to 1.0
    float transcendence; // 0.0 to 1.0
    float equilibrium;   // 0.0 to 1.0
    float stability;     // 0.0 to 1.0
    bool isBalanced;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static BalanceTranscendent FromJson(const nlohmann::json& j);
};

struct SynthesisTranscendent {
    std::string synthesisId;
    std::string name;
    float synthesis;     // 0.0 to 1.0
    float transcendence; // 0.0 to 1.0
    float integration;   // 0.0 to 1.0
    float fusion;        // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static SynthesisTranscendent FromJson(const nlohmann::json& j);
};

// Core engine class
class TranscendentUnityEngine {
public:
    // Initialization
    static void Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Transcendent Unity Structure operations
    static std::string CreateTranscendentUnityStructure(const std::string& name);
    static bool DestroyTranscendentUnityStructure(const std::string& transcendentId);
    static std::shared_ptr<TranscendentUnityStructure> GetTranscendentUnityStructure(const std::string& transcendentId);
    static std::vector<TranscendentUnityStructure> GetAllTranscendentUnityStructures();
    static bool ElevateTranscendence(const std::string& transcendentId, float amount);
    static bool ExpandUnity(const std::string& transcendentId, float amount);
    static bool CultivateHarmony(const std::string& transcendentId, float amount);
    static bool EstablishBalance(const std::string& transcendentId, float amount);
    static bool AchieveSynthesis(const std::string& transcendentId, float amount);
    
    // Unity Transcendent operations
    static std::string CreateUnityTranscendent(const std::string& name);
    static bool DestroyUnityTranscendent(const std::string& unityId);
    static std::shared_ptr<UnityTranscendent> GetUnityTranscendent(const std::string& unityId);
    static std::vector<UnityTranscendent> GetAllUnityTranscendents();
    static bool StrengthenCohesion(const std::string& unityId, float amount);
    static bool RealizeOneness(const std::string& unityId, float amount);
    static bool DeclareUnified(const std::string& unityId);
    
    // Harmony Transcendent operations
    static std::string CreateHarmonyTranscendent(const std::string& name);
    static bool DestroyHarmonyTranscendent(const std::string& harmonyId);
    static std::shared_ptr<HarmonyTranscendent> GetHarmonyTranscendent(const std::string& harmonyId);
    static std::vector<HarmonyTranscendent> GetAllHarmonyTranscendents();
    static bool AmplifyResonance(const std::string& harmonyId, float amount);
    static bool PerfectAlignment(const std::string& harmonyId, float amount);
    
    // Balance Transcendent operations
    static std::string CreateBalanceTranscendent(const std::string& name);
    static bool DestroyBalanceTranscendent(const std::string& balanceId);
    static std::shared_ptr<BalanceTranscendent> GetBalanceTranscendent(const std::string& balanceId);
    static std::vector<BalanceTranscendent> GetAllBalanceTranscendents();
    static bool RestoreEquilibrium(const std::string& balanceId, float amount);
    static bool EnsureStability(const std::string& balanceId, float amount);
    static bool DeclareBalanced(const std::string& balanceId);
    
    // Synthesis Transcendent operations
    static std::string CreateSynthesisTranscendent(const std::string& name);
    static bool DestroySynthesisTranscendent(const std::string& synthesisId);
    static std::shared_ptr<SynthesisTranscendent> GetSynthesisTranscendent(const std::string& synthesisId);
    static std::vector<SynthesisTranscendent> GetAllSynthesisTranscendents();
    static bool DeepenIntegration(const std::string& synthesisId, float amount);
    static bool CatalyzeFusion(const std::string& synthesisId, float amount);
    
    // Metrics and reporting
    static nlohmann::json GetTranscendentUnityMetrics();
    static nlohmann::json GenerateTranscendentUnityReport();
    
private:
    static bool s_initialized;
    static std::mutex s_transcendentMutex;
    static std::mutex s_unityMutex;
    static std::mutex s_harmonyMutex;
    static std::mutex s_balanceMutex;
    static std::mutex s_synthesisMutex;
    
    static std::vector<std::shared_ptr<TranscendentUnityStructure>> s_transcendentStructures;
    static std::vector<std::shared_ptr<UnityTranscendent>> s_unityTranscendents;
    static std::vector<std::shared_ptr<HarmonyTranscendent>> s_harmonyTranscendents;
    static std::vector<std::shared_ptr<BalanceTranscendent>> s_balanceTranscendents;
    static std::vector<std::shared_ptr<SynthesisTranscendent>> s_synthesisTranscendents;
    
    static std::atomic<int64_t> s_transcendentCounter;
    static std::atomic<int64_t> s_unityCounter;
    static std::atomic<int64_t> s_harmonyCounter;
    static std::atomic<int64_t> s_balanceCounter;
    static std::atomic<int64_t> s_synthesisCounter;
};

} // namespace TranscendentUnity
