#pragma once

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <map>
#include <nlohmann/json.hpp>

namespace EternalRadiance {

// Forward declarations
struct EternalRadianceStructure;
struct GlowEternal;
struct ShineEternal;
struct BrightnessEternal;
struct IntensityEternal;
struct LuminescenceEternal;
struct TransparencyEternal;

using json = nlohmann::json;

// Core data structures

struct EternalRadianceStructure {
    std::string id;
    std::string name;
    std::string description;
    
    // Eternal radiance properties
    float glow;
    float shine;
    float brightness;
    float intensity;
    float luminescence;
    float transparency;
    
    // Metadata
    std::string createdAt;
    std::string modifiedAt;
    bool isActive;
    
    EternalRadianceStructure() : glow(0.0f), shine(0.0f), brightness(0.0f), 
                                 intensity(0.0f), luminescence(0.0f), transparency(0.0f), 
                                 isActive(true) {}
    
    json ToJson() const;
    static EternalRadianceStructure FromJson(const json& j);
};

struct GlowEternal {
    std::string id;
    std::string name;
    std::string parentId;
    
    float glow;
    float shine;
    float brightness;
    float intensity;
    float luminescence;
    float transparency;
    
    bool isEternal;
    std::string eternalizedAt;
    
    GlowEternal() : glow(0.0f), shine(0.0f), brightness(0.0f), 
                    intensity(0.0f), luminescence(0.0f), transparency(0.0f), 
                    isEternal(false) {}
    
    json ToJson() const;
    static GlowEternal FromJson(const json& j);
};

struct ShineEternal {
    std::string id;
    std::string name;
    std::string parentId;
    
    float glow;
    float shine;
    float brightness;
    float intensity;
    float luminescence;
    float transparency;
    
    bool isEternal;
    std::string eternalizedAt;
    
    ShineEternal() : glow(0.0f), shine(0.0f), brightness(0.0f), 
                     intensity(0.0f), luminescence(0.0f), transparency(0.0f), 
                     isEternal(false) {}
    
    json ToJson() const;
    static ShineEternal FromJson(const json& j);
};

struct BrightnessEternal {
    std::string id;
    std::string name;
    std::string parentId;
    
    float glow;
    float shine;
    float brightness;
    float intensity;
    float luminescence;
    float transparency;
    
    bool isEternal;
    std::string eternalizedAt;
    
    BrightnessEternal() : glow(0.0f), shine(0.0f), brightness(0.0f), 
                          intensity(0.0f), luminescence(0.0f), transparency(0.0f), 
                          isEternal(false) {}
    
    json ToJson() const;
    static BrightnessEternal FromJson(const json& j);
};

struct IntensityEternal {
    std::string id;
    std::string name;
    std::string parentId;
    
    float glow;
    float shine;
    float brightness;
    float intensity;
    float luminescence;
    float transparency;
    
    bool isEternal;
    std::string eternalizedAt;
    
    IntensityEternal() : glow(0.0f), shine(0.0f), brightness(0.0f), 
                         intensity(0.0f), luminescence(0.0f), transparency(0.0f), 
                         isEternal(false) {}
    
    json ToJson() const;
    static IntensityEternal FromJson(const json& j);
};

struct LuminescenceEternal {
    std::string id;
    std::string name;
    std::string parentId;
    
    float glow;
    float shine;
    float brightness;
    float intensity;
    float luminescence;
    float transparency;
    
    bool isEternal;
    std::string eternalizedAt;
    
    LuminescenceEternal() : glow(0.0f), shine(0.0f), brightness(0.0f), 
                            intensity(0.0f), luminescence(0.0f), transparency(0.0f), 
                            isEternal(false) {}
    
    json ToJson() const;
    static LuminescenceEternal FromJson(const json& j);
};

struct TransparencyEternal {
    std::string id;
    std::string name;
    std::string parentId;
    
    float glow;
    float shine;
    float brightness;
    float intensity;
    float luminescence;
    float transparency;
    
    bool isEternal;
    std::string eternalizedAt;
    
    TransparencyEternal() : glow(0.0f), shine(0.0f), brightness(0.0f), 
                            intensity(0.0f), luminescence(0.0f), transparency(0.0f), 
                            isEternal(false) {}
    
    json ToJson() const;
    static TransparencyEternal FromJson(const json& j);
};

// Main engine class
class EternalRadianceEngine {
public:
    // Initialization
    static bool Initialize();
    static void Shutdown();
    static bool IsInitialized();
    
    // Eternal radiance structure operations
    static std::string CreateEternalRadianceStructure(const std::string& name);
    static std::shared_ptr<EternalRadianceStructure> GetEternalRadianceStructure(const std::string& id);
    static bool UpdateEternalRadianceStructure(const std::string& id, const EternalRadianceStructure& structure);
    static bool DeleteEternalRadianceStructure(const std::string& id);
    static std::vector<std::string> GetAllEternalRadianceStructureIds();
    static std::vector<std::shared_ptr<EternalRadianceStructure>> GetAllEternalRadianceStructures();
    
    // Glow eternal operations
    static std::string CreateGlowEternal(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<GlowEternal> GetGlowEternal(const std::string& id);
    static bool UpdateGlowEternal(const std::string& id, const GlowEternal& glow);
    static bool DeleteGlowEternal(const std::string& id);
    static std::vector<std::string> GetAllGlowEternalIds();
    static std::vector<std::shared_ptr<GlowEternal>> GetAllGlowEternals();
    
    // Shine eternal operations
    static std::string CreateShineEternal(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<ShineEternal> GetShineEternal(const std::string& id);
    static bool UpdateShineEternal(const std::string& id, const ShineEternal& shine);
    static bool DeleteShineEternal(const std::string& id);
    static std::vector<std::string> GetAllShineEternalIds();
    static std::vector<std::shared_ptr<ShineEternal>> GetAllShineEternals();
    
    // Brightness eternal operations
    static std::string CreateBrightnessEternal(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<BrightnessEternal> GetBrightnessEternal(const std::string& id);
    static bool UpdateBrightnessEternal(const std::string& id, const BrightnessEternal& brightness);
    static bool DeleteBrightnessEternal(const std::string& id);
    static std::vector<std::string> GetAllBrightnessEternalIds();
    static std::vector<std::shared_ptr<BrightnessEternal>> GetAllBrightnessEternals();
    
    // Intensity eternal operations
    static std::string CreateIntensityEternal(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<IntensityEternal> GetIntensityEternal(const std::string& id);
    static bool UpdateIntensityEternal(const std::string& id, const IntensityEternal& intensity);
    static bool DeleteIntensityEternal(const std::string& id);
    static std::vector<std::string> GetAllIntensityEternalIds();
    static std::vector<std::shared_ptr<IntensityEternal>> GetAllIntensityEternals();
    
    // Luminescence eternal operations
    static std::string CreateLuminescenceEternal(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<LuminescenceEternal> GetLuminescenceEternal(const std::string& id);
    static bool UpdateLuminescenceEternal(const std::string& id, const LuminescenceEternal& luminescence);
    static bool DeleteLuminescenceEternal(const std::string& id);
    static std::vector<std::string> GetAllLuminescenceEternalIds();
    static std::vector<std::shared_ptr<LuminescenceEternal>> GetAllLuminescenceEternals();
    
    // Transparency eternal operations
    static std::string CreateTransparencyEternal(const std::string& name, const std::string& parentId = "");
    static std::shared_ptr<TransparencyEternal> GetTransparencyEternal(const std::string& id);
    static bool UpdateTransparencyEternal(const std::string& id, const TransparencyEternal& transparency);
    static bool DeleteTransparencyEternal(const std::string& id);
    static std::vector<std::string> GetAllTransparencyEternalIds();
    static std::vector<std::shared_ptr<TransparencyEternal>> GetAllTransparencyEternals();
    
    // Action operations
    static bool ExpandEternalRadiance(const std::string& id);
    static bool AmplifyGlow(const std::string& id);
    static bool IncreaseShine(const std::string& id);
    static bool EnhanceBrightness(const std::string& id);
    static bool IntensifyRadiance(const std::string& id);
    static bool SpreadLuminescence(const std::string& id);
    static bool ClarifyTransparency(const std::string& id);
    
    // Glow eternal actions
    static bool IntensifyGlowEternal(const std::string& id);
    static bool AmplifyShineEternal(const std::string& id);
    static bool DeclareGlowEternal(const std::string& id);
    
    // Shine eternal actions
    static bool IncreaseBrightnessEternal(const std::string& id);
    static bool IntensifyShineEternal(const std::string& id);
    static bool DeclareShineEternal(const std::string& id);
    
    // Brightness eternal actions
    static bool BrightenEternal(const std::string& id);
    static bool PolishEternal(const std::string& id);
    static bool DeclareBrightnessEternal(const std::string& id);
    
    // Intensity eternal actions
    static bool StrengthenEternal(const std::string& id);
    static bool DeepenEternal(const std::string& id);
    static bool DeclareIntensityEternal(const std::string& id);
    
    // Luminescence eternal actions
    static bool IlluminateEternal(const std::string& id);
    static bool RadiateEternal(const std::string& id);
    static bool DeclareLuminescenceEternal(const std::string& id);
    
    // Transparency eternal actions
    static bool MakeEternalTransparent(const std::string& id);
    static bool IncreaseEternalClarity(const std::string& id);
    static bool DeclareTransparencyEternal(const std::string& id);
    
    // Utility
    static void ClearAll();
    static size_t GetTotalStructureCount();
    
private:
    static std::atomic<bool> s_initialized;
    
    static std::mutex s_structureMutex;
    static std::mutex s_glowMutex;
    static std::mutex s_shineMutex;
    static std::mutex s_brightnessMutex;
    static std::mutex s_intensityMutex;
    static std::mutex s_luminescenceMutex;
    static std::mutex s_transparencyMutex;
    
    static std::map<std::string, std::shared_ptr<EternalRadianceStructure>> s_structures;
    static std::map<std::string, std::shared_ptr<GlowEternal>> s_glowEternals;
    static std::map<std::string, std::shared_ptr<ShineEternal>> s_shineEternals;
    static std::map<std::string, std::shared_ptr<BrightnessEternal>> s_brightnessEternals;
    static std::map<std::string, std::shared_ptr<IntensityEternal>> s_intensityEternals;
    static std::map<std::string, std::shared_ptr<LuminescenceEternal>> s_luminescenceEternals;
    static std::map<std::string, std::shared_ptr<TransparencyEternal>> s_transparencyEternals;
    
    static std::string GenerateId();
    static std::string GetCurrentTimestamp();
};

} // namespace EternalRadiance
