#pragma once
#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <functional>
#include <nlohmann/json.hpp>

namespace Integration {

struct LayerStatus {
    int layerId;
    std::string layerName;
    bool initialized;
    bool active;
    float health;
    int64_t lastTick;
    nlohmann::json metrics;
};

struct SystemOrchestration {
    std::string orchestrationId;
    std::string name;
    std::vector<int> involvedLayers;
    std::string orchestrationType;
    nlohmann::json parameters;
    bool executing;
    int64_t startedTimestamp;
};

struct CrossLayerBridge {
    std::string bridgeId;
    int sourceLayer;
    int destinationLayer;
    std::string bridgeType;
    float bandwidth;
    float latency;
    bool active;
};

struct IntegrationHealth {
    float overallHealth;
    float layerSynchronization;
    float dataFlowEfficiency;
    float orchestrationCapability;
    int activeLayers;
    int activeBridges;
};

class SovereignIntegrationEngine {
public:
    static void Init();
    static void Shutdown();
    
    // Layer Management
    static bool InitializeLayer(int layerId);
    static bool ActivateLayer(int layerId);
    static bool DeactivateLayer(int layerId);
    static LayerStatus GetLayerStatus(int layerId);
    static std::vector<LayerStatus> GetAllLayerStatuses();
    static bool IsLayerHealthy(int layerId);
    
    // Cross-Layer Orchestration
    static std::string CreateOrchestration(const std::string& name,
                                           const std::vector<int>& layers,
                                           const std::string& type,
                                           const nlohmann::json& parameters);
    static bool ExecuteOrchestration(const std::string& orchestrationId);
    static bool PauseOrchestration(const std::string& orchestrationId);
    static bool ResumeOrchestration(const std::string& orchestrationId);
    static bool StopOrchestration(const std::string& orchestrationId);
    static SystemOrchestration GetOrchestration(const std::string& orchestrationId);
    static std::vector<SystemOrchestration> GetAllOrchestrations();
    
    // Cross-Layer Bridges
    static std::string EstablishBridge(int sourceLayer, int destinationLayer, const std::string& bridgeType);
    static bool ActivateBridge(const std::string& bridgeId);
    static bool DeactivateBridge(const std::string& bridgeId);
    static bool TransferData(const std::string& bridgeId, const nlohmann::json& data);
    static CrossLayerBridge GetBridge(const std::string& bridgeId);
    static std::vector<CrossLayerBridge> GetAllBridges();
    static std::vector<CrossLayerBridge> GetBridgesForLayer(int layerId);
    
    // System-Wide Operations
    static bool InitializeAllLayers();
    static bool ActivateAllLayers();
    static bool DeactivateAllLayers();
    static bool EmergencyShutdown();
    static bool SystemReboot();
    
    // Health & Monitoring
    static IntegrationHealth CalculateSystemHealth();
    static nlohmann::json GetSystemMetrics();
    static nlohmann::json GenerateSystemReport();
    static nlohmann::json GenerateLayerDependencyGraph();
    
    // Event System
    static void BroadcastEvent(const std::string& eventType, const nlohmann::json& eventData);
    static void SubscribeToLayerEvents(int layerId, std::function<void(const nlohmann::json&)> callback);
    static void UnsubscribeFromLayerEvents(int layerId);
    
    static void OnTick();
    static bool IsAlive();
    static int64_t GetSystemUptime();

private:
    static std::mutex s_mutex;
    static bool s_initialized;
    static std::map<int, LayerStatus> s_layerStatuses;
    static std::map<std::string, SystemOrchestration> s_orchestrations;
    static std::map<std::string, CrossLayerBridge> s_bridges;
    static std::map<int, std::vector<std::function<void(const nlohmann::json&)>>> s_eventCallbacks;
    static int64_t s_tickCount;
    static int64_t s_startTimestamp;
    
    static void InitializeLayerDependencies();
    static void PropagateEvent(int layerId, const std::string& eventType, const nlohmann::json& eventData);
};

} // namespace Integration
