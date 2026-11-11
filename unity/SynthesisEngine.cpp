#include "unity/SynthesisEngine.hpp"
#include <chrono>
#include <algorithm>
#include <queue>
#include <set>

namespace RawrXD {
namespace Sovereign {
namespace Unity {

std::vector<LayerIntegration> SynthesisEngine::s_integrations;
std::vector<EmergentProperty> SynthesisEngine::s_emergentProperties;
std::mutex SynthesisEngine::s_mutex;
bool SynthesisEngine::s_alive = false;
SystemCoherence SynthesisEngine::s_lastCoherence;

void SynthesisEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_integrations.clear();
    s_emergentProperties.clear();
    s_alive = true;
    s_lastCoherence = {0.0f, 0.0f, 0.0f, 0.0f, 0};
    
    // Create default integrations between all layers
    std::vector<std::string> layers = {
        "Fabric", "Cognition", "Federation", "Society", "Teleology",
        "Knowledge", "Ethics", "Aesthetics", "Spirituality"
    };
    
    for (size_t i = 0; i < layers.size(); i++) {
        for (size_t j = i + 1; j < layers.size(); j++) {
            CreateIntegration(layers[i], layers[j], "bidirectional");
        }
    }
}

void SynthesisEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_alive) return;
    
    // Update coherence metrics
    UpdateCoherenceMetrics();
    
    // Strengthen active integrations over time
    for (auto& integration : s_integrations) {
        if (integration.isActive) {
            integration.strength = std::min(1.0f, integration.strength + 0.0001f);
        }
    }
    
    // Update emergent properties
    for (auto& property : s_emergentProperties) {
        float newLevel = MeasureEmergenceLevel(property.propertyId);
        property.emergenceLevel = property.emergenceLevel * 0.9f + newLevel * 0.1f;
        property.isStable = property.emergenceLevel > 0.7f;
    }
}

bool SynthesisEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_alive;
}

std::string SynthesisEngine::CreateIntegration(const std::string& sourceLayer,
                                                  const std::string& targetLayer,
                                                  const std::string& integrationType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    LayerIntegration integration;
    integration.integrationId = "integration_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    integration.sourceLayer = sourceLayer;
    integration.targetLayer = targetLayer;
    integration.integrationType = integrationType;
    integration.strength = 0.5f;
    integration.isActive = true;
    
    s_integrations.push_back(integration);
    return integration.integrationId;
}

bool SynthesisEngine::StrengthenIntegration(const std::string& integrationId, float delta) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    LayerIntegration* integration = FindIntegration(integrationId);
    if (!integration) return false;
    
    integration->strength = std::min(1.0f, std::max(0.0f, integration->strength + delta));
    return true;
}

bool SynthesisEngine::ActivateIntegration(const std::string& integrationId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    LayerIntegration* integration = FindIntegration(integrationId);
    if (!integration) return false;
    
    integration->isActive = true;
    return true;
}

bool SynthesisEngine::DeactivateIntegration(const std::string& integrationId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    LayerIntegration* integration = FindIntegration(integrationId);
    if (!integration) return false;
    
    integration->isActive = false;
    return true;
}

std::string SynthesisEngine::IdentifyEmergentProperty(const std::string& name,
                                                       const std::string& description,
                                                       const std::vector<std::string>& contributingLayers) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    EmergentProperty property;
    property.propertyId = "emergent_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    property.name = name;
    property.description = description;
    property.contributingLayers = contributingLayers;
    property.emergenceLevel = 0.0f;
    property.isStable = false;
    
    s_emergentProperties.push_back(property);
    return property.propertyId;
}

float SynthesisEngine::MeasureEmergenceLevel(const std::string& propertyId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    EmergentProperty* property = FindEmergentProperty(propertyId);
    if (!property) return 0.0f;
    
    // Calculate emergence based on integration strength between contributing layers
    float totalStrength = 0.0f;
    int connectionCount = 0;
    
    for (size_t i = 0; i < property->contributingLayers.size(); i++) {
        for (size_t j = i + 1; j < property->contributingLayers.size(); j++) {
            for (const auto& integration : s_integrations) {
                if ((integration.sourceLayer == property->contributingLayers[i] &&
                     integration.targetLayer == property->contributingLayers[j]) ||
                    (integration.sourceLayer == property->contributingLayers[j] &&
                     integration.targetLayer == property->contributingLayers[i])) {
                    if (integration.isActive) {
                        totalStrength += integration.strength;
                        connectionCount++;
                    }
                }
            }
        }
    }
    
    if (connectionCount == 0) return 0.0f;
    return totalStrength / connectionCount;
}

bool SynthesisEngine::StabilizeEmergentProperty(const std::string& propertyId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    EmergentProperty* property = FindEmergentProperty(propertyId);
    if (!property) return false;
    
    // Strengthen all integrations between contributing layers
    for (const auto& layer1 : property->contributingLayers) {
        for (const auto& layer2 : property->contributingLayers) {
            if (layer1 != layer2) {
                for (auto& integration : s_integrations) {
                    if ((integration.sourceLayer == layer1 && integration.targetLayer == layer2) ||
                        (integration.sourceLayer == layer2 && integration.targetLayer == layer1)) {
                        integration.strength = std::min(1.0f, integration.strength + 0.1f);
                    }
                }
            }
        }
    }
    
    property->isStable = true;
    return true;
}

SystemCoherence SynthesisEngine::CalculateSystemCoherence() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    SystemCoherence coherence;
    coherence.layerAlignment = CalculateLayerAlignment();
    coherence.crossLayerHarmony = CalculateCrossLayerHarmony();
    coherence.emergentStability = CalculateEmergentStability();
    coherence.overallCoherence = (coherence.layerAlignment + coherence.crossLayerHarmony + coherence.emergentStability) / 3.0f;
    coherence.measuredAt = std::chrono::steady_clock::now().time_since_epoch().count();
    
    s_lastCoherence = coherence;
    return coherence;
}

float SynthesisEngine::CalculateLayerAlignment() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    if (s_integrations.empty()) return 0.0f;
    
    float totalAlignment = 0.0f;
    int activeCount = 0;
    
    for (const auto& integration : s_integrations) {
        if (integration.isActive) {
            totalAlignment += integration.strength;
            activeCount++;
        }
    }
    
    return activeCount > 0 ? totalAlignment / activeCount : 0.0f;
}

float SynthesisEngine::CalculateCrossLayerHarmony() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    // Calculate harmony as the variance of integration strengths
    if (s_integrations.empty()) return 0.0f;
    
    float sum = 0.0f;
    float sumSquared = 0.0f;
    int count = 0;
    
    for (const auto& integration : s_integrations) {
        if (integration.isActive) {
            sum += integration.strength;
            sumSquared += integration.strength * integration.strength;
            count++;
        }
    }
    
    if (count == 0) return 0.0f;
    
    float mean = sum / count;
    float variance = (sumSquared / count) - (mean * mean);
    
    // Higher harmony = lower variance
    return std::max(0.0f, 1.0f - variance);
}

float SynthesisEngine::CalculateEmergentStability() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    if (s_emergentProperties.empty()) return 0.0f;
    
    int stableCount = 0;
    for (const auto& property : s_emergentProperties) {
        if (property.isStable) stableCount++;
    }
    
    return (float)stableCount / s_emergentProperties.size();
}

std::vector<std::string> SynthesisEngine::FindIntegrationPath(const std::string& fromLayer,
                                                                 const std::string& toLayer) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    // BFS to find shortest path
    std::queue<std::pair<std::string, std::vector<std::string>>> queue;
    std::set<std::string> visited;
    
    queue.push({fromLayer, {fromLayer}});
    visited.insert(fromLayer);
    
    while (!queue.empty()) {
        auto [current, path] = queue.front();
        queue.pop();
        
        if (current == toLayer) {
            return path;
        }
        
        for (const auto& integration : s_integrations) {
            if (integration.isActive) {
                std::string next;
                if (integration.sourceLayer == current) {
                    next = integration.targetLayer;
                } else if (integration.targetLayer == current) {
                    next = integration.sourceLayer;
                }
                
                if (!next.empty() && visited.find(next) == visited.end()) {
                    visited.insert(next);
                    auto newPath = path;
                    newPath.push_back(next);
                    queue.push({next, newPath});
                }
            }
        }
    }
    
    return {}; // No path found
}

std::vector<std::string> SynthesisEngine::GetCriticalIntegrations() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<std::string> critical;
    
    for (const auto& integration : s_integrations) {
        if (integration.isActive && integration.strength < 0.3f) {
            critical.push_back(integration.integrationId);
        }
    }
    
    return critical;
}

std::vector<std::string> SynthesisEngine::GetUnstableEmergentProperties() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<std::string> unstable;
    
    for (const auto& property : s_emergentProperties) {
        if (!property.isStable) {
            unstable.push_back(property.propertyId);
        }
    }
    
    return unstable;
}

nlohmann::json SynthesisEngine::GetIntegration(const std::string& integrationId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    LayerIntegration* integration = FindIntegration(integrationId);
    if (!integration) return nlohmann::json{{"error", "integration not found"}};
    
    nlohmann::json j;
    j["integrationId"] = integration->integrationId;
    j["sourceLayer"] = integration->sourceLayer;
    j["targetLayer"] = integration->targetLayer;
    j["integrationType"] = integration->integrationType;
    j["strength"] = integration->strength;
    j["isActive"] = integration->isActive;
    return j;
}

nlohmann::json SynthesisEngine::GetIntegrations() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json integrations = nlohmann::json::array();
    for (const auto& integration : s_integrations) {
        nlohmann::json j;
        j["integrationId"] = integration.integrationId;
        j["sourceLayer"] = integration.sourceLayer;
        j["targetLayer"] = integration.targetLayer;
        j["strength"] = integration.strength;
        j["isActive"] = integration.isActive;
        integrations.push_back(j);
    }
    return integrations;
}

nlohmann::json SynthesisEngine::GetEmergentProperty(const std::string& propertyId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    EmergentProperty* property = FindEmergentProperty(propertyId);
    if (!property) return nlohmann::json{{"error", "property not found"}};
    
    nlohmann::json j;
    j["propertyId"] = property->propertyId;
    j["name"] = property->name;
    j["description"] = property->description;
    j["contributingLayers"] = property->contributingLayers;
    j["emergenceLevel"] = property->emergenceLevel;
    j["isStable"] = property->isStable;
    return j;
}

nlohmann::json SynthesisEngine::GetEmergentProperties() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json properties = nlohmann::json::array();
    for (const auto& property : s_emergentProperties) {
        nlohmann::json j;
        j["propertyId"] = property.propertyId;
        j["name"] = property.name;
        j["emergenceLevel"] = property.emergenceLevel;
        j["isStable"] = property.isStable;
        properties.push_back(j);
    }
    return properties;
}

nlohmann::json SynthesisEngine::GetCoherenceReport() {
    SystemCoherence coherence = CalculateSystemCoherence();
    
    nlohmann::json report;
    report["overallCoherence"] = coherence.overallCoherence;
    report["layerAlignment"] = coherence.layerAlignment;
    report["crossLayerHarmony"] = coherence.crossLayerHarmony;
    report["emergentStability"] = coherence.emergentStability;
    report["measuredAt"] = coherence.measuredAt;
    report["criticalIntegrations"] = GetCriticalIntegrations();
    report["unstableProperties"] = GetUnstableEmergentProperties();
    
    return report;
}

nlohmann::json SynthesisEngine::GetSynthesisMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json metrics;
    metrics["totalIntegrations"] = s_integrations.size();
    metrics["totalEmergentProperties"] = s_emergentProperties.size();
    
    size_t activeIntegrations = 0;
    float avgStrength = 0.0f;
    
    for (const auto& integration : s_integrations) {
        if (integration.isActive) activeIntegrations++;
        avgStrength += integration.strength;
    }
    
    metrics["activeIntegrations"] = activeIntegrations;
    metrics["averageIntegrationStrength"] = s_integrations.empty() ? 0.0f : avgStrength / s_integrations.size();
    metrics["stableEmergentProperties"] = [&]() {
        size_t count = 0;
        for (const auto& p : s_emergentProperties) if (p.isStable) count++;
        return count;
    }();
    
    return metrics;
}

nlohmann::json SynthesisEngine::GenerateUnityReport() {
    nlohmann::json report;
    report["synthesis"] = GetSynthesisMetrics();
    report["coherence"] = GetCoherenceReport();
    report["emergentProperties"] = GetEmergentProperties();
    report["status"] = "unity_achieved";
    report["timestamp"] = std::chrono::steady_clock::now().time_since_epoch().count();
    return report;
}

LayerIntegration* SynthesisEngine::FindIntegration(const std::string& integrationId) {
    for (auto& integration : s_integrations) {
        if (integration.integrationId == integrationId) return &integration;
    }
    return nullptr;
}

EmergentProperty* SynthesisEngine::FindEmergentProperty(const std::string& propertyId) {
    for (auto& property : s_emergentProperties) {
        if (property.propertyId == propertyId) return &property;
    }
    return nullptr;
}

void SynthesisEngine::UpdateCoherenceMetrics() {
    // Called during OnTick to update coherence
    s_lastCoherence = CalculateSystemCoherence();
}

} // namespace Unity
} // namespace Sovereign
} // namespace RawrXD
