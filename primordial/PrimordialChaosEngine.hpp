#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>

namespace PrimordialChaos {

// Forward declarations
struct PrimordialChaosStructure;
struct ChaosPrimordial;
struct VoidPrimordial;
struct AbyssPrimordial;
struct FluxPrimordial;

// Core data structures
struct PrimordialChaosStructure {
    std::string primordialId;
    std::string name;
    float primordiality;   // 0.0 to 1.0
    float chaos;           // 0.0 to 1.0
    float voidness;        // 0.0 to 1.0
    float abyss;           // 0.0 to 1.0
    float flux;            // 0.0 to 1.0
    int64_t createdAt;
    int64_t lastModified;
    bool isActive;
    
    nlohmann::json ToJson() const;
    static PrimordialChaosStructure FromJson(const nlohmann::json& j);
};

struct ChaosPrimordial {
    std::string chaosId;
    std::string name;
    float chaos;           // 0.0 to 1.0
    float primordiality;   // 0.0 to 1.0
    float disorder;    // 0.0 to 1.0
    float turbulence;  // 0.0 to 1.0
    bool isChaotic;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static ChaosPrimordial FromJson(const nlohmann::json& j);
};

struct VoidPrimordial {
    std::string voidId;
    std::string name;
    float voidness;        // 0.0 to 1.0
    float primordiality;   // 0.0 to 1.0
    float emptiness;   // 0.0 to 1.0
    float nullity;     // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static VoidPrimordial FromJson(const nlohmann::json& j);
};

struct AbyssPrimordial {
    std::string abyssId;
    std::string name;
    float abyss;           // 0.0 to 1.0
    float primordiality;   // 0.0 to 1.0
    float depth;       // 0.0 to 1.0
    float darkness;    // 0.0 to 1.0
    bool isAbyssal;
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static AbyssPrimordial FromJson(const nlohmann::json& j);
};

struct FluxPrimordial {
    std::string fluxId;
    std::string name;
    float flux;            // 0.0 to 1.0
    float primordiality;   // 0.0 to 1.0
    float change;      // 0.0 to 1.0
    float flow;        // 0.0 to 1.0
    int64_t createdAt;
    
    nlohmann::json ToJson() const;
    static FluxPrimordial FromJson(const nlohmann::json& j);
};

// Core engine class
class PrimordialChaosEngine {
public:
    // Initialization
    static void Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Primordial Chaos Structure operations
    static std::string CreatePrimordialChaosStructure(const std::string& name);
    static bool DestroyPrimordialChaosStructure(const std::string& primordialId);
    static std::shared_ptr<PrimordialChaosStructure> GetPrimordialChaosStructure(const std::string& primordialId);
    static std::vector<PrimordialChaosStructure> GetAllPrimordialChaosStructures();
    static bool AwakenPrimordiality(const std::string& primordialId, float amount);
    static bool UnleashChaos(const std::string& primordialId, float amount);
    static bool EmbraceVoid(const std::string& primordialId, float amount);
    static bool PlumbAbyss(const std::string& primordialId, float amount);
    static bool ChannelFlux(const std::string& primordialId, float amount);
    
    // Chaos Primordial operations
    static std::string CreateChaosPrimordial(const std::string& name);
    static bool DestroyChaosPrimordial(const std::string& chaosId);
    static std::shared_ptr<ChaosPrimordial> GetChaosPrimordial(const std::string& chaosId);
    static std::vector<ChaosPrimordial> GetAllChaosPrimordials();
    static bool SowDisorder(const std::string& chaosId, float amount);
    static bool StirTurbulence(const std::string& chaosId, float amount);
    static bool DeclareChaotic(const std::string& chaosId);
    
    // Void Primordial operations
    static std::string CreateVoidPrimordial(const std::string& name);
    static bool DestroyVoidPrimordial(const std::string& voidId);
    static std::shared_ptr<VoidPrimordial> GetVoidPrimordial(const std::string& voidId);
    static std::vector<VoidPrimordial> GetAllVoidPrimordials();
    static bool DeepenEmptiness(const std::string& voidId, float amount);
    static bool EmbraceNullity(const std::string& voidId, float amount);
    
    // Abyss Primordial operations
    static std::string CreateAbyssPrimordial(const std::string& name);
    static bool DestroyAbyssPrimordial(const std::string& abyssId);
    static std::shared_ptr<AbyssPrimordial> GetAbyssPrimordial(const std::string& abyssId);
    static std::vector<AbyssPrimordial> GetAllAbyssPrimordials();
    static bool FathomDepth(const std::string& abyssId, float amount);
    static bool ShroudDarkness(const std::string& abyssId, float amount);
    static bool DeclareAbyssal(const std::string& abyssId);
    
    // Flux Primordial operations
    static std::string CreateFluxPrimordial(const std::string& name);
    static bool DestroyFluxPrimordial(const std::string& fluxId);
    static std::shared_ptr<FluxPrimordial> GetFluxPrimordial(const std::string& fluxId);
    static std::vector<FluxPrimordial> GetAllFluxPrimordials();
    static bool AccelerateChange(const std::string& fluxId, float amount);
    static bool DirectFlow(const std::string& fluxId, float amount);
    
    // Metrics and reporting
    static nlohmann::json GetPrimordialChaosMetrics();
    static nlohmann::json GeneratePrimordialChaosReport();
    
private:
    static bool s_initialized;
    static std::mutex s_primordialMutex;
    static std::mutex s_chaosMutex;
    static std::mutex s_voidMutex;
    static std::mutex s_abyssMutex;
    static std::mutex s_fluxMutex;
    
    static std::vector<std::shared_ptr<PrimordialChaosStructure>> s_primordialStructures;
    static std::vector<std::shared_ptr<ChaosPrimordial>> s_chaosPrimordials;
    static std::vector<std::shared_ptr<VoidPrimordial>> s_voidPrimordials;
    static std::vector<std::shared_ptr<AbyssPrimordial>> s_abyssPrimordials;
    static std::vector<std::shared_ptr<FluxPrimordial>> s_fluxPrimordials;
    
    static std::atomic<int64_t> s_primordialCounter;
    static std::atomic<int64_t> s_chaosCounter;
    static std::atomic<int64_t> s_voidCounter;
    static std::atomic<int64_t> s_abyssCounter;
    static std::atomic<int64_t> s_fluxCounter;
};

} // namespace PrimordialChaos
