#pragma once
#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>

namespace Astral {

struct UniversalPortal {
    std::string portalId;
    std::string name;
    std::string sourceUniverse;
    std::string destinationUniverse;
    float stability;
    float throughput;
    bool active;
    int64_t establishedTimestamp;
};

struct CosmicGateway {
    std::string gatewayId;
    std::string name;
    std::string gatewayType; // "transport", "communication", "energy", "matter"
    std::vector<std::string> connectedPortals;
    float bandwidth;
    float latency;
    int64_t commissionedTimestamp;
};

struct MultiversalBridge {
    std::string bridgeId;
    std::string name;
    std::string bridgeClass; // "primary", "secondary", "auxiliary", "emergency"
    std::vector<std::string> spanUniverses;
    float structuralIntegrity;
    float trafficLoad;
    int64_t constructedTimestamp;
};

struct TranscendentConduit {
    std::string conduitId;
    std::string name;
    std::string conduitType; // "data", "energy", "consciousness", "matter"
    float flowCapacity;
    float efficiency;
    std::map<std::string, float> currentFlows;
    int64_t activatedTimestamp;
};

struct NexusConnection {
    std::string connectionId;
    std::string sourceId;
    std::string destinationId;
    std::string connectionType;
    float strength;
    float reliability;
    int64_t establishedTimestamp;
};

class AstralNexusEngine {
public:
    static void Init();
    static void Shutdown();
    
    static std::string EstablishUniversalPortal(const std::string& name,
                                                const std::string& sourceUniverse,
                                                const std::string& destinationUniverse);
    static bool ActivatePortal(const std::string& portalId);
    static bool DeactivatePortal(const std::string& portalId);
    static bool StabilizePortal(const std::string& portalId, float stabilityLevel);
    static UniversalPortal GetPortal(const std::string& portalId);
    static std::vector<UniversalPortal> GetAllPortals();
    static std::vector<UniversalPortal> GetActivePortals();
    static std::vector<UniversalPortal> GetPortalsByUniverse(const std::string& universeId);
    
    static std::string CommissionCosmicGateway(const std::string& name,
                                               const std::string& gatewayType);
    static bool ConnectPortalToGateway(const std::string& portalId, const std::string& gatewayId);
    static bool DisconnectPortalFromGateway(const std::string& portalId, const std::string& gatewayId);
    static bool OptimizeGatewayBandwidth(const std::string& gatewayId, float bandwidth);
    static CosmicGateway GetGateway(const std::string& gatewayId);
    static std::vector<CosmicGateway> GetAllGateways();
    static std::vector<CosmicGateway> GetGatewaysByType(const std::string& gatewayType);
    
    static std::string ConstructMultiversalBridge(const std::string& name,
                                                  const std::string& bridgeClass,
                                                  const std::vector<std::string>& universes);
    static bool ReinforceBridge(const std::string& bridgeId, float integrityBoost);
    static bool RouteTrafficThroughBridge(const std::string& bridgeId, float trafficAmount);
    static MultiversalBridge GetBridge(const std::string& bridgeId);
    static std::vector<MultiversalBridge> GetAllBridges();
    static std::vector<MultiversalBridge> GetBridgesByClass(const std::string& bridgeClass);
    
    static std::string ActivateTranscendentConduit(const std::string& name,
                                                     const std::string& conduitType,
                                                     float flowCapacity);
    static bool AdjustConduitFlow(const std::string& conduitId, const std::string& channel, float flowRate);
    static bool OptimizeConduitEfficiency(const std::string& conduitId, float efficiency);
    static TranscendentConduit GetConduit(const std::string& conduitId);
    static std::vector<TranscendentConduit> GetAllConduits();
    static std::vector<TranscendentConduit> GetConduitsByType(const std::string& conduitType);
    
    static std::string CreateNexusConnection(const std::string& sourceId,
                                           const std::string& destinationId,
                                           const std::string& connectionType);
    static bool StrengthenConnection(const std::string& connectionId, float strengthBoost);
    static bool SeverConnection(const std::string& connectionId);
    static NexusConnection GetConnection(const std::string& connectionId);
    static std::vector<NexusConnection> GetAllConnections();
    static std::vector<NexusConnection> GetConnectionsByNode(const std::string& nodeId);
    
    static float CalculateNexusConnectivity();
    static float CalculateAverageThroughput();
    static nlohmann::json GetNexusMetrics();
    static nlohmann::json GenerateNexusReport();
    
    static void OnTick();
    static bool IsAlive();

private:
    static std::mutex s_mutex;
    static bool s_initialized;
    static std::map<std::string, UniversalPortal> s_portals;
    static std::map<std::string, CosmicGateway> s_gateways;
    static std::map<std::string, MultiversalBridge> s_bridges;
    static std::map<std::string, TranscendentConduit> s_conduits;
    static std::map<std::string, NexusConnection> s_connections;
    static int64_t s_tickCount;
};

} // namespace Astral
