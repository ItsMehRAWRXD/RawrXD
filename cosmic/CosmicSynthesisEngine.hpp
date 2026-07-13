#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace CosmicSynthesis {

// Forward declarations
struct CosmicSynthesisStructure;
struct SynthesisCosmic;
struct HarmonyCosmic;
struct BalanceCosmic;
struct UnityCosmic;

// Core data structures
struct CosmicSynthesisStructure {
    std::string cosmicId;
    std::string name;
    float cosmicness;      // 0.0 to 1.0
    float synthesis;       // 0.0 to 1.0
    float harmony;         // 0.0 to 1.0
    float balance;         // 0.0 to 1.0
    float unity;           // 0.0 to 1.0
    int64_t createdAt;
    int64_t lastModified;
    bool isActive;
    
    nlohmann::json ToJson() const;
    static CosmicSynthesisStructure FromJson(const nlohmann::json& j);
};

struct SynthesisCosmic {
    std::string synthesisId;
    std::string name;
    float synthesis;       // 0.0 to 1.0
    float cosmicness;      // 0.0 to 1.0
    float integration;     // 0.0 to 1.0
    float fusion;          // 0.0 to 1.0
    bool isSynthesized;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static SynthesisCosmic FromJson(const nlohmann::json& j);
};

struct HarmonyCosmic {
    std::string harmonyId;
    std::string name;
    float harmony;         // 0.0 to 1.0
    float cosmicness;      // 0.0 to 1.0
    float resonance;     // 0.0 to 1.0
    float alignment;       // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static HarmonyCosmic FromJson(const nlohmann::json& j);
};

struct BalanceCosmic {
    std::string balanceId;
    std::string name;
    float balance;         // 0.0 to 1.0
    float cosmicness;      // 0.0 to 1.0
    float equilibrium;   // 0.0 to 1.0
    float stability;     // 0.0 to 1.0
    bool isBalanced;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static BalanceCosmic FromJson(const nlohmann::json& j);
};

struct UnityCosmic {
    std::string unityId;
    std::string name;
    float unity;           // 0.0 to 1.0
    float cosmicness;        // 0.0 to 1.0
    float cohesion;      // 0.0 to 1.0
    float oneness;       // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static UnityCosmic FromJson(const nlohmann::json& j);
};

// Core engine class
class CosmicSynthesisEngine {
public:
    // Initialization
    static void Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Cosmic Synthesis Structure operations
    static std::string CreateCosmicSynthesisStructure(const std::string& name);
    static bool DestroyCosmicSynthesisStructure(const std::string& cosmicId);
    static std::shared_ptr<CosmicSynthesisStructure> GetCosmicSynthesisStructure(const std::string& cosmicId);
    static std::vector<CosmicSynthesisStructure> GetAllCosmicSynthesisStructures();
    static bool ExpandCosmicness(const std::string& cosmicId, float amount);
    static bool CatalyzeSynthesis(const std::string& cosmicId, float amount);
    static bool AttuneHarmony(const std::string& cosmicId, float amount);
    static bool EstablishBalance(const std::string& cosmicId, float amount);
    static bool ForgeUnity(const std::string& cosmicId, float amount);
    
    // Synthesis Cosmic operations
    static std::string CreateSynthesisCosmic(const std::string& name);
    static bool DestroySynthesisCosmic(const std::string& synthesisId);
    static std::shared_ptr<SynthesisCosmic> GetSynthesisCosmic(const std::string& synthesisId);
    static std::vector<SynthesisCosmic> GetAllSynthesisCosmics();
    static bool DeepenIntegration(const std::string& synthesisId, float amount);
    static bool CatalyzeFusion(const std::string& synthesisId, float amount);
    static bool DeclareSynthesized(const std::string& synthesisId);
    
    // Harmony Cosmic operations
    static std::string CreateHarmonyCosmic(const std::string& name);
    static bool DestroyHarmonyCosmic(const std::string& harmonyId);
    static std::shared_ptr<HarmonyCosmic> GetHarmonyCosmic(const std::string& harmonyId);
    static std::vector<HarmonyCosmic> GetAllHarmonyCosmics();
    static bool AmplifyResonance(const std::string& harmonyId, float amount);
    static bool PerfectAlignment(const std::string& harmonyId, float amount);
    
    // Balance Cosmic operations
    static std::string CreateBalanceCosmic(const std::string& name);
    static bool DestroyBalanceCosmic(const std::string& balanceId);
    static std::shared_ptr<BalanceCosmic> GetBalanceCosmic(const std::string& balanceId);
    static std::vector<BalanceCosmic> GetAllBalanceCosmics();
    static bool RestoreEquilibrium(const std::string& balanceId, float amount);
    static bool EnsureStability(const std::string& balanceId, float amount);
    static bool DeclareBalanced(const std::string& balanceId);
    
    // Unity Cosmic operations
    static std::string CreateUnityCosmic(const std::string& name);
    static bool DestroyUnityCosmic(const std::string& unityId);
    static std::shared_ptr<UnityCosmic> GetUnityCosmic(const std::string& unityId);
    static std::vector<UnityCosmic> GetAllUnityCosmics();
    static bool StrengthenCohesion(const std::string& unityId, float amount);
    static bool RealizeOneness(const std::string& unityId, float amount);
    
    // Metrics and reporting
    static nlohmann::json GetCosmicSynthesisMetrics();
    static nlohmann::json GenerateCosmicSynthesisReport();
    
private:
    static bool s_initialized;
    static std::mutex s_cosmicMutex;
    static std::mutex s_synthesisMutex;
    static std::mutex s_harmonyMutex;
    static std::mutex s_balanceMutex;
    static std::mutex s_unityMutex;
    
    static std::vector<std::shared_ptr<CosmicSynthesisStructure>> s_cosmicStructures;
    static std::vector<std::shared_ptr<SynthesisCosmic>> s_synthesisCosmics;
    static std::vector<std::shared_ptr<HarmonyCosmic>> s_harmonyCosmics;
    static std::vector<std::shared_ptr<BalanceCosmic>> s_balanceCosmics;
    static std::vector<std::shared_ptr<UnityCosmic>> s_unityCosmics;
    
    static std::atomic<int64_t> s_cosmicCounter;
    static std::atomic<int64_t> s_synthesisCounter;
    static std::atomic<int64_t> s_harmonyCounter;
    static std::atomic<int64_t> s_balanceCounter;
    static std::atomic<int64_t> s_unityCounter;
};

} // namespace CosmicSynthesis
