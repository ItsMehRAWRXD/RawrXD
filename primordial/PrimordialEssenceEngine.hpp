#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <nlohmann/json.hpp>

namespace PrimordialEssence {

// Forward declarations
class PrimordialEssenceEngine;

// Event callback type
using PrimordialEventCallback = std::function<void(const std::string& eventType, const nlohmann::json& data)>;

// Primordial Essence Structure - Core entity
struct PrimordialEssenceStructure {
    std::string primordialId;
    std::string name;
    std::string description;
    
    // Primordial attributes (0.0 - 1.0)
    float primordiality;      // Degree of primordial essence
    float origin;             // Degree of origin
    float source;             // Degree of source
    float root;               // Degree of root
    float foundation;         // Degree of foundation
    float ground;             // Degree of ground
    
    // Metadata
    std::string createdAt;
    std::string updatedAt;
    bool isActive;
    bool isPrimordial;        // Whether achieved primordial state
    
    PrimordialEssenceStructure();
    nlohmann::json ToJson() const;
    static PrimordialEssenceStructure FromJson(const nlohmann::json& json);
};

// Origin Absolute - Represents primordial origin
struct OriginAbsolute {
    std::string originId;
    std::string name;
    std::string description;
    
    float origin;             // Degree of origin
    float beginning;          // Degree of beginning
    float inception;          // Degree of inception
    
    bool isOriginated;        // Whether declared originated
    
    std::string createdAt;
    std::string updatedAt;
    
    OriginAbsolute();
    nlohmann::json ToJson() const;
    static OriginAbsolute FromJson(const nlohmann::json& json);
};

// Source Absolute - Represents primordial source
struct SourceAbsolute {
    std::string sourceId;
    std::string name;
    std::string description;
    
    float source;             // Degree of source
    float wellspring;         // Degree of wellspring
    float fountain;           // Degree of fountain
    
    bool isSourced;           // Whether declared sourced
    
    std::string createdAt;
    std::string updatedAt;
    
    SourceAbsolute();
    nlohmann::json ToJson() const;
    static SourceAbsolute FromJson(const nlohmann::json& json);
};

// Root Absolute - Represents primordial root
struct RootAbsolute {
    std::string rootId;
    std::string name;
    std::string description;
    
    float root;               // Degree of root
    float basis;              // Degree of basis
    float core;               // Degree of core
    
    bool isRooted;            // Whether declared rooted
    
    std::string createdAt;
    std::string updatedAt;
    
    RootAbsolute();
    nlohmann::json ToJson() const;
    static RootAbsolute FromJson(const nlohmann::json& json);
};

// Foundation Absolute - Represents primordial foundation
struct FoundationAbsolute {
    std::string foundationId;
    std::string name;
    std::string description;
    
    float foundation;         // Degree of foundation
    float groundwork;         // Degree of groundwork
    float underpinning;       // Degree of underpinning
    
    bool isFounded;           // Whether declared founded
    
    std::string createdAt;
    std::string updatedAt;
    
    FoundationAbsolute();
    nlohmann::json ToJson() const;
    static FoundationAbsolute FromJson(const nlohmann::json& json);
};

// Ground Absolute - Represents primordial ground
struct GroundAbsolute {
    std::string groundId;
    std::string name;
    std::string description;
    
    float ground;             // Degree of ground
    float soil;               // Degree of soil
    float bedrock;            // Degree of bedrock
    
    bool isGrounded;          // Whether declared grounded
    
    std::string createdAt;
    std::string updatedAt;
    
    GroundAbsolute();
    nlohmann::json ToJson() const;
    static GroundAbsolute FromJson(const nlohmann::json& json);
};

// Main engine class
class PrimordialEssenceEngine {
public:
    // Initialization
    static bool Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Primordial Essence Structure operations
    static std::string CreatePrimordialEssenceStructure(const std::string& name);
    static bool DestroyPrimordialEssenceStructure(const std::string& primordialId);
    static std::shared_ptr<PrimordialEssenceStructure> GetPrimordialEssenceStructure(const std::string& primordialId);
    static std::vector<PrimordialEssenceStructure> GetAllPrimordialEssenceStructures();
    static bool UpdatePrimordialEssenceStructure(const std::string& primordialId, const PrimordialEssenceStructure& structure);
    
    // Origin Absolute operations
    static std::string CreateOriginAbsolute(const std::string& name);
    static bool DestroyOriginAbsolute(const std::string& originId);
    static std::shared_ptr<OriginAbsolute> GetOriginAbsolute(const std::string& originId);
    static std::vector<OriginAbsolute> GetAllOriginAbsolutes();
    
    // Source Absolute operations
    static std::string CreateSourceAbsolute(const std::string& name);
    static bool DestroySourceAbsolute(const std::string& sourceId);
    static std::shared_ptr<SourceAbsolute> GetSourceAbsolute(const std::string& sourceId);
    static std::vector<SourceAbsolute> GetAllSourceAbsolutes();
    
    // Root Absolute operations
    static std::string CreateRootAbsolute(const std::string& name);
    static bool DestroyRootAbsolute(const std::string& rootId);
    static std::shared_ptr<RootAbsolute> GetRootAbsolute(const std::string& rootId);
    static std::vector<RootAbsolute> GetAllRootAbsolutes();
    
    // Foundation Absolute operations
    static std::string CreateFoundationAbsolute(const std::string& name);
    static bool DestroyFoundationAbsolute(const std::string& foundationId);
    static std::shared_ptr<FoundationAbsolute> GetFoundationAbsolute(const std::string& foundationId);
    static std::vector<FoundationAbsolute> GetAllFoundationAbsolutes();
    
    // Ground Absolute operations
    static std::string CreateGroundAbsolute(const std::string& name);
    static bool DestroyGroundAbsolute(const std::string& groundId);
    static std::shared_ptr<GroundAbsolute> GetGroundAbsolute(const std::string& groundId);
    static std::vector<GroundAbsolute> GetAllGroundAbsolutes();
    
    // Primordial operations
    static bool DeepenPrimordiality(const std::string& primordialId, float amount);
    static bool TraceOrigin(const std::string& primordialId, float amount);
    static bool TapSource(const std::string& primordialId, float amount);
    static bool ExtendRoot(const std::string& primordialId, float amount);
    static bool LayFoundation(const std::string& primordialId, float amount);
    static bool EstablishGround(const std::string& primordialId, float amount);
    
    // Origin operations
    static bool CommenceBeginning(const std::string& originId, float amount);
    static bool MarkInception(const std::string& originId, float amount);
    static bool DeclareOriginated(const std::string& originId);
    
    // Source operations
    static bool OpenWellspring(const std::string& sourceId, float amount);
    static bool ActivateFountain(const std::string& sourceId, float amount);
    static bool DeclareSourced(const std::string& sourceId);
    
    // Root operations
    static bool StrengthenBasis(const std::string& rootId, float amount);
    static bool FortifyCore(const std::string& rootId, float amount);
    static bool DeclareRooted(const std::string& rootId);
    
    // Foundation operations
    static bool PrepareGroundwork(const std::string& foundationId, float amount);
    static bool SecureUnderpinning(const std::string& foundationId, float amount);
    static bool DeclareFounded(const std::string& foundationId);
    
    // Ground operations
    static bool CultivateSoil(const std::string& groundId, float amount);
    static bool ExposeBedrock(const std::string& groundId, float amount);
    static bool DeclareGrounded(const std::string& groundId);
    
    // Metrics
    static nlohmann::json GetPrimordialEssenceMetrics();
    
    // Event system
    static void RegisterEventCallback(PrimordialEventCallback callback);
    static void UnregisterEventCallback(PrimordialEventCallback callback);
    
private:
    static std::atomic<bool> s_initialized;
    static std::mutex s_primordialMutex;
    static std::mutex s_originMutex;
    static std::mutex s_sourceMutex;
    static std::mutex s_rootMutex;
    static std::mutex s_foundationMutex;
    static std::mutex s_groundMutex;
    static std::mutex s_callbackMutex;
    
    static std::map<std::string, PrimordialEssenceStructure> s_primordialStructures;
    static std::map<std::string, OriginAbsolute> s_originAbsolutes;
    static std::map<std::string, SourceAbsolute> s_sourceAbsolutes;
    static std::map<std::string, RootAbsolute> s_rootAbsolutes;
    static std::map<std::string, FoundationAbsolute> s_foundationAbsolutes;
    static std::map<std::string, GroundAbsolute> s_groundAbsolutes;
    static std::vector<PrimordialEventCallback> s_eventCallbacks;
    
    static void EmitEvent(const std::string& eventType, const nlohmann::json& data);
    static std::string GenerateId();
    static std::string GetCurrentTimestamp();
};

} // namespace PrimordialEssence
