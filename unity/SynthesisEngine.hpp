#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Unity {

struct LayerIntegration {
    std::string integrationId;
    std::string sourceLayer;
    std::string targetLayer;
    std::string integrationType;
    float strength;
    bool isActive;
};

struct EmergentProperty {
    std::string propertyId;
    std::string name;
    std::string description;
    std::vector<std::string> contributingLayers;
    float emergenceLevel;
    bool isStable;
};

struct SystemCoherence {
    float overallCoherence;
    float layerAlignment;
    float crossLayerHarmony;
    float emergentStability;
    int64_t measuredAt;
};

class SynthesisEngine {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();

    static std::string CreateIntegration(const std::string& sourceLayer,
                                          const std::string& targetLayer,
                                          const std::string& integrationType);
    static bool StrengthenIntegration(const std::string& integrationId, float delta);
    static bool ActivateIntegration(const std::string& integrationId);
    static bool DeactivateIntegration(const std::string& integrationId);
    
    static std::string IdentifyEmergentProperty(const std::string& name,
                                                   const std::string& description,
                                                   const std::vector<std::string>& contributingLayers);
    static float MeasureEmergenceLevel(const std::string& propertyId);
    static bool StabilizeEmergentProperty(const std::string& propertyId);
    
    static SystemCoherence CalculateSystemCoherence();
    static float CalculateLayerAlignment();
    static float CalculateCrossLayerHarmony();
    static float CalculateEmergentStability();
    
    static std::vector<std::string> FindIntegrationPath(const std::string& fromLayer,
                                                         const std::string& toLayer);
    static std::vector<std::string> GetCriticalIntegrations();
    static std::vector<std::string> GetUnstableEmergentProperties();
    
    static nlohmann::json GetIntegration(const std::string& integrationId);
    static nlohmann::json GetIntegrations();
    static nlohmann::json GetEmergentProperty(const std::string& propertyId);
    static nlohmann::json GetEmergentProperties();
    static nlohmann::json GetCoherenceReport();
    
    static nlohmann::json GetSynthesisMetrics();
    static nlohmann::json GenerateUnityReport();

private:
    static std::vector<LayerIntegration> s_integrations;
    static std::vector<EmergentProperty> s_emergentProperties;
    static std::mutex s_mutex;
    static bool s_alive;
    static SystemCoherence s_lastCoherence;
    
    static LayerIntegration* FindIntegration(const std::string& integrationId);
    static EmergentProperty* FindEmergentProperty(const std::string& propertyId);
    static void UpdateCoherenceMetrics();
};

} // namespace Unity
} // namespace Sovereign
} // namespace RawrXD
