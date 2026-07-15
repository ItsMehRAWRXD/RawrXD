#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <nlohmann/json.hpp>

namespace InfiniteLight {

// Forward declarations
class InfiniteLightEngine;

// Event callback type
using InfiniteEventCallback = std::function<void(const std::string& eventType, const nlohmann::json& data)>;

// Infinite Light Structure - Core entity
struct InfiniteLightStructure {
    std::string infiniteId;
    std::string name;
    std::string description;
    
    // Infinite attributes (0.0 - 1.0)
    float infiniteLight;      // Degree of infinite light
    float radiance;           // Degree of radiance
    float brilliance;         // Degree of brilliance
    float luminosity;         // Degree of luminosity
    float illumination;       // Degree of illumination
    float clarity;            // Degree of clarity
    
    // Metadata
    std::string createdAt;
    std::string updatedAt;
    bool isActive;
    bool isInfiniteLight;     // Whether achieved infinite light state
    
    InfiniteLightStructure();
    nlohmann::json ToJson() const;
    static InfiniteLightStructure FromJson(const nlohmann::json& json);
};

// Radiance Absolute - Represents infinite radiance
struct RadianceAbsolute {
    std::string radianceId;
    std::string name;
    std::string description;
    
    float radiance;           // Degree of radiance
    float glow;               // Degree of glow
    float shine;              // Degree of shine
    
    bool isRadiant;           // Whether declared radiant
    
    std::string createdAt;
    std::string updatedAt;
    
    RadianceAbsolute();
    nlohmann::json ToJson() const;
    static RadianceAbsolute FromJson(const nlohmann::json& json);
};

// Brilliance Absolute - Represents infinite brilliance
struct BrillianceAbsolute {
    std::string brillianceId;
    std::string name;
    std::string description;
    
    float brilliance;         // Degree of brilliance
    float brightness;         // Degree of brightness
    float intensity;          // Degree of intensity
    
    bool isBrilliant;         // Whether declared brilliant
    
    std::string createdAt;
    std::string updatedAt;
    
    BrillianceAbsolute();
    nlohmann::json ToJson() const;
    static BrillianceAbsolute FromJson(const nlohmann::json& json);
};

// Luminosity Absolute - Represents infinite luminosity
struct LuminosityAbsolute {
    std::string luminosityId;
    std::string name;
    std::string description;
    
    float luminosity;         // Degree of luminosity
    float brightness;         // Degree of brightness
    float shine;              // Degree of shine
    
    bool isLuminous;          // Whether declared luminous
    
    std::string createdAt;
    std::string updatedAt;
    
    LuminosityAbsolute();
    nlohmann::json ToJson() const;
    static LuminosityAbsolute FromJson(const nlohmann::json& json);
};

// Illumination Absolute - Represents infinite illumination
struct IlluminationAbsolute {
    std::string illuminationId;
    std::string name;
    std::string description;
    
    float illumination;       // Degree of illumination
    float enlightenment;      // Degree of enlightenment
    float revelation;         // Degree of revelation
    
    bool isIlluminated;       // Whether declared illuminated
    
    std::string createdAt;
    std::string updatedAt;
    
    IlluminationAbsolute();
    nlohmann::json ToJson() const;
    static IlluminationAbsolute FromJson(const nlohmann::json& json);
};

// Clarity Absolute - Represents infinite clarity
struct ClarityAbsolute {
    std::string clarityId;
    std::string name;
    std::string description;
    
    float clarity;            // Degree of clarity
    float transparency;       // Degree of transparency
    float lucidity;           // Degree of lucidity
    
    bool isClear;             // Whether declared clear
    
    std::string createdAt;
    std::string updatedAt;
    
    ClarityAbsolute();
    nlohmann::json ToJson() const;
    static ClarityAbsolute FromJson(const nlohmann::json& json);
};

// Main engine class
class InfiniteLightEngine {
public:
    // Initialization
    static bool Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Infinite Light Structure operations
    static std::string CreateInfiniteLightStructure(const std::string& name);
    static bool DestroyInfiniteLightStructure(const std::string& infiniteId);
    static std::shared_ptr<InfiniteLightStructure> GetInfiniteLightStructure(const std::string& infiniteId);
    static std::vector<InfiniteLightStructure> GetAllInfiniteLightStructures();
    static bool UpdateInfiniteLightStructure(const std::string& infiniteId, const InfiniteLightStructure& structure);
    
    // Radiance Absolute operations
    static std::string CreateRadianceAbsolute(const std::string& name);
    static bool DestroyRadianceAbsolute(const std::string& radianceId);
    static std::shared_ptr<RadianceAbsolute> GetRadianceAbsolute(const std::string& radianceId);
    static std::vector<RadianceAbsolute> GetAllRadianceAbsolutes();
    
    // Brilliance Absolute operations
    static std::string CreateBrillianceAbsolute(const std::string& name);
    static bool DestroyBrillianceAbsolute(const std::string& brillianceId);
    static std::shared_ptr<BrillianceAbsolute> GetBrillianceAbsolute(const std::string& brillianceId);
    static std::vector<BrillianceAbsolute> GetAllBrillianceAbsolutes();
    
    // Luminosity Absolute operations
    static std::string CreateLuminosityAbsolute(const std::string& name);
    static bool DestroyLuminosityAbsolute(const std::string& luminosityId);
    static std::shared_ptr<LuminosityAbsolute> GetLuminosityAbsolute(const std::string& luminosityId);
    static std::vector<LuminosityAbsolute> GetAllLuminosityAbsolutes();
    
    // Illumination Absolute operations
    static std::string CreateIlluminationAbsolute(const std::string& name);
    static bool DestroyIlluminationAbsolute(const std::string& illuminationId);
    static std::shared_ptr<IlluminationAbsolute> GetIlluminationAbsolute(const std::string& illuminationId);
    static std::vector<IlluminationAbsolute> GetAllIlluminationAbsolutes();
    
    // Clarity Absolute operations
    static std::string CreateClarityAbsolute(const std::string& name);
    static bool DestroyClarityAbsolute(const std::string& clarityId);
    static std::shared_ptr<ClarityAbsolute> GetClarityAbsolute(const std::string& clarityId);
    static std::vector<ClarityAbsolute> GetAllClarityAbsolutes();
    
    // Infinite operations
    static bool ExpandInfiniteLight(const std::string& infiniteId, float amount);
    static bool AmplifyRadiance(const std::string& infiniteId, float amount);
    static bool IncreaseBrilliance(const std::string& infiniteId, float amount);
    static bool EnhanceLuminosity(const std::string& infiniteId, float amount);
    static bool SpreadIllumination(const std::string& infiniteId, float amount);
    static bool SharpenClarity(const std::string& infiniteId, float amount);
    
    // Radiance operations
    static bool IntensifyGlow(const std::string& radianceId, float amount);
    static bool AmplifyShine(const std::string& radianceId, float amount);
    static bool DeclareRadiant(const std::string& radianceId);
    
    // Brilliance operations
    static bool IncreaseBrightness(const std::string& brillianceId, float amount);
    static bool Intensify(const std::string& brillianceId, float amount);
    static bool DeclareBrilliant(const std::string& brillianceId);
    
    // Luminosity operations
    static bool Brighten(const std::string& luminosityId, float amount);
    static bool PolishShine(const std::string& luminosityId, float amount);
    static bool DeclareLuminous(const std::string& luminosityId);
    
    // Illumination operations
    static bool Enlighten(const std::string& illuminationId, float amount);
    static bool Reveal(const std::string& illuminationId, float amount);
    static bool DeclareIlluminated(const std::string& illuminationId);
    
    // Clarity operations
    static bool MakeTransparent(const std::string& clarityId, float amount);
    static bool IncreaseLucidity(const std::string& clarityId, float amount);
    static bool DeclareClear(const std::string& clarityId);
    
    // Metrics
    static nlohmann::json GetInfiniteLightMetrics();
    
    // Event system
    static void RegisterEventCallback(InfiniteEventCallback callback);
    static void UnregisterEventCallback(InfiniteEventCallback callback);
    
private:
    static std::atomic<bool> s_initialized;
    static std::mutex s_infiniteMutex;
    static std::mutex s_radianceMutex;
    static std::mutex s_brillianceMutex;
    static std::mutex s_luminosityMutex;
    static std::mutex s_illuminationMutex;
    static std::mutex s_clarityMutex;
    static std::mutex s_callbackMutex;
    
    static std::map<std::string, InfiniteLightStructure> s_infiniteStructures;
    static std::map<std::string, RadianceAbsolute> s_radianceAbsolutes;
    static std::map<std::string, BrillianceAbsolute> s_brillianceAbsolutes;
    static std::map<std::string, LuminosityAbsolute> s_luminosityAbsolutes;
    static std::map<std::string, IlluminationAbsolute> s_illuminationAbsolutes;
    static std::map<std::string, ClarityAbsolute> s_clarityAbsolutes;
    static std::vector<InfiniteEventCallback> s_eventCallbacks;
    
    static void EmitEvent(const std::string& eventType, const nlohmann::json& data);
    static std::string GenerateId();
    static std::string GetCurrentTimestamp();
};

} // namespace InfiniteLight
