#include "astral/AstralNexusEngine.hpp"
#include <chrono>
#include <algorithm>

namespace Astral {

std::mutex AstralNexusEngine::s_mutex;
bool AstralNexusEngine::s_initialized = false;
std::map<std::string, UniversalPortal> AstralNexusEngine::s_portals;
std::map<std::string, CosmicGateway> AstralNexusEngine::s_gateways;
std::map<std::string, MultiversalBridge> AstralNexusEngine::s_bridges;
std::map<std::string, TranscendentConduit> AstralNexusEngine::s_conduits;
std::map<std::string, NexusConnection> AstralNexusEngine::s_connections;
int64_t AstralNexusEngine::s_tickCount = 0;

void AstralNexusEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
}

void AstralNexusEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = false;
    s_portals.clear();
    s_gateways.clear();
    s_bridges.clear();
    s_conduits.clear();
    s_connections.clear();
}

std::string AstralNexusEngine::EstablishUniversalPortal(const std::string& name,
                                                        const std::string& sourceUniverse,
                                                        const std::string& destinationUniverse) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int portalCounter = 0;
    std::string portalId = "universal_portal_" + std::to_string(++portalCounter);
    
    UniversalPortal portal;
    portal.portalId = portalId;
    portal.name = name;
    portal.sourceUniverse = sourceUniverse;
    portal.destinationUniverse = destinationUniverse;
    portal.stability = 1.0f;
    portal.throughput = 1000.0f;
    portal.active = false;
    portal.establishedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_portals[portalId] = portal;
    return portalId;
}

bool AstralNexusEngine::ActivatePortal(const std::string& portalId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_portals.find(portalId);
    if (it == s_portals.end()) return false;
    it->second.active = true;
    return true;
}

bool AstralNexusEngine::DeactivatePortal(const std::string& portalId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_portals.find(portalId);
    if (it == s_portals.end()) return false;
    it->second.active = false;
    return true;
}

bool AstralNexusEngine::StabilizePortal(const std::string& portalId, float stabilityLevel) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_portals.find(portalId);
    if (it == s_portals.end()) return false;
    it->second.stability = std::min(1.0f, std::max(0.0f, stabilityLevel));
    return true;
}

UniversalPortal AstralNexusEngine::GetPortal(const std::string& portalId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_portals.find(portalId);
    if (it != s_portals.end()) return it->second;
    return UniversalPortal{};
}

std::vector<UniversalPortal> AstralNexusEngine::GetAllPortals() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalPortal> result;
    for (const auto& [id, portal] : s_portals) {
        result.push_back(portal);
    }
    return result;
}

std::vector<UniversalPortal> AstralNexusEngine::GetActivePortals() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalPortal> result;
    for (const auto& [id, portal] : s_portals) {
        if (portal.active) result.push_back(portal);
    }
    return result;
}

std::vector<UniversalPortal> AstralNexusEngine::GetPortalsByUniverse(const std::string& universeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalPortal> result;
    for (const auto& [id, portal] : s_portals) {
        if (portal.sourceUniverse == universeId || portal.destinationUniverse == universeId) {
            result.push_back(portal);
        }
    }
    return result;
}

std::string AstralNexusEngine::CommissionCosmicGateway(const std::string& name,
                                                         const std::string& gatewayType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int gatewayCounter = 0;
    std::string gatewayId = "cosmic_gateway_" + std::to_string(++gatewayCounter);
    
    CosmicGateway gateway;
    gateway.gatewayId = gatewayId;
    gateway.name = name;
    gateway.gatewayType = gatewayType;
    gateway.bandwidth = 1000.0f;
    gateway.latency = 1.0f;
    gateway.commissionedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_gateways[gatewayId] = gateway;
    return gatewayId;
}

bool AstralNexusEngine::ConnectPortalToGateway(const std::string& portalId, const std::string& gatewayId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto gatewayIt = s_gateways.find(gatewayId);
    if (gatewayIt == s_gateways.end()) return false;
    gatewayIt->second.connectedPortals.push_back(portalId);
    return true;
}

bool AstralNexusEngine::DisconnectPortalFromGateway(const std::string& portalId, const std::string& gatewayId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto gatewayIt = s_gateways.find(gatewayId);
    if (gatewayIt == s_gateways.end()) return false;
    auto& portals = gatewayIt->second.connectedPortals;
    portals.erase(std::remove(portals.begin(), portals.end(), portalId), portals.end());
    return true;
}

bool AstralNexusEngine::OptimizeGatewayBandwidth(const std::string& gatewayId, float bandwidth) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_gateways.find(gatewayId);
    if (it == s_gateways.end()) return false;
    it->second.bandwidth = bandwidth;
    return true;
}

CosmicGateway AstralNexusEngine::GetGateway(const std::string& gatewayId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_gateways.find(gatewayId);
    if (it != s_gateways.end()) return it->second;
    return CosmicGateway{};
}

std::vector<CosmicGateway> AstralNexusEngine::GetAllGateways() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicGateway> result;
    for (const auto& [id, gateway] : s_gateways) {
        result.push_back(gateway);
    }
    return result;
}

std::vector<CosmicGateway> AstralNexusEngine::GetGatewaysByType(const std::string& gatewayType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicGateway> result;
    for (const auto& [id, gateway] : s_gateways) {
        if (gateway.gatewayType == gatewayType) result.push_back(gateway);
    }
    return result;
}

std::string AstralNexusEngine::ConstructMultiversalBridge(const std::string& name,
                                                          const std::string& bridgeClass,
                                                          const std::vector<std::string>& universes) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int bridgeCounter = 0;
    std::string bridgeId = "multiversal_bridge_" + std::to_string(++bridgeCounter);
    
    MultiversalBridge bridge;
    bridge.bridgeId = bridgeId;
    bridge.name = name;
    bridge.bridgeClass = bridgeClass;
    bridge.spanUniverses = universes;
    bridge.structuralIntegrity = 1.0f;
    bridge.trafficLoad = 0.0f;
    bridge.constructedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_bridges[bridgeId] = bridge;
    return bridgeId;
}

bool AstralNexusEngine::ReinforceBridge(const std::string& bridgeId, float integrityBoost) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_bridges.find(bridgeId);
    if (it == s_bridges.end()) return false;
    it->second.structuralIntegrity = std::min(1.0f, it->second.structuralIntegrity + integrityBoost);
    return true;
}

bool AstralNexusEngine::RouteTrafficThroughBridge(const std::string& bridgeId, float trafficAmount) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_bridges.find(bridgeId);
    if (it == s_bridges.end()) return false;
    it->second.trafficLoad = std::min(1.0f, it->second.trafficLoad + trafficAmount);
    return true;
}

MultiversalBridge AstralNexusEngine::GetBridge(const std::string& bridgeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_bridges.find(bridgeId);
    if (it != s_bridges.end()) return it->second;
    return MultiversalBridge{};
}

std::vector<MultiversalBridge> AstralNexusEngine::GetAllBridges() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<MultiversalBridge> result;
    for (const auto& [id, bridge] : s_bridges) {
        result.push_back(bridge);
    }
    return result;
}

std::vector<MultiversalBridge> AstralNexusEngine::GetBridgesByClass(const std::string& bridgeClass) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<MultiversalBridge> result;
    for (const auto& [id, bridge] : s_bridges) {
        if (bridge.bridgeClass == bridgeClass) result.push_back(bridge);
    }
    return result;
}

std::string AstralNexusEngine::ActivateTranscendentConduit(const std::string& name,
                                                           const std::string& conduitType,
                                                           float flowCapacity) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int conduitCounter = 0;
    std::string conduitId = "transcendent_conduit_" + std::to_string(++conduitCounter);
    
    TranscendentConduit conduit;
    conduit.conduitId = conduitId;
    conduit.name = name;
    conduit.conduitType = conduitType;
    conduit.flowCapacity = flowCapacity;
    conduit.efficiency = 1.0f;
    conduit.activatedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_conduits[conduitId] = conduit;
    return conduitId;
}

bool AstralNexusEngine::AdjustConduitFlow(const std::string& conduitId, const std::string& channel, float flowRate) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_conduits.find(conduitId);
    if (it == s_conduits.end()) return false;
    it->second.currentFlows[channel] = flowRate;
    return true;
}

bool AstralNexusEngine::OptimizeConduitEfficiency(const std::string& conduitId, float efficiency) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_conduits.find(conduitId);
    if (it == s_conduits.end()) return false;
    it->second.efficiency = std::min(1.0f, std::max(0.0f, efficiency));
    return true;
}

TranscendentConduit AstralNexusEngine::GetConduit(const std::string& conduitId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_conduits.find(conduitId);
    if (it != s_conduits.end()) return it->second;
    return TranscendentConduit{};
}

std::vector<TranscendentConduit> AstralNexusEngine::GetAllConduits() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<TranscendentConduit> result;
    for (const auto& [id, conduit] : s_conduits) {
        result.push_back(conduit);
    }
    return result;
}

std::vector<TranscendentConduit> AstralNexusEngine::GetConduitsByType(const std::string& conduitType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<TranscendentConduit> result;
    for (const auto& [id, conduit] : s_conduits) {
        if (conduit.conduitType == conduitType) result.push_back(conduit);
    }
    return result;
}

std::string AstralNexusEngine::CreateNexusConnection(const std::string& sourceId,
                                                       const std::string& destinationId,
                                                       const std::string& connectionType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int connectionCounter = 0;
    std::string connectionId = "nexus_connection_" + std::to_string(++connectionCounter);
    
    NexusConnection connection;
    connection.connectionId = connectionId;
    connection.sourceId = sourceId;
    connection.destinationId = destinationId;
    connection.connectionType = connectionType;
    connection.strength = 1.0f;
    connection.reliability = 1.0f;
    connection.establishedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_connections[connectionId] = connection;
    return connectionId;
}

bool AstralNexusEngine::StrengthenConnection(const std::string& connectionId, float strengthBoost) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_connections.find(connectionId);
    if (it == s_connections.end()) return false;
    it->second.strength = std::min(1.0f, it->second.strength + strengthBoost);
    return true;
}

bool AstralNexusEngine::SeverConnection(const std::string& connectionId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_connections.find(connectionId);
    if (it == s_connections.end()) return false;
    s_connections.erase(it);
    return true;
}

NexusConnection AstralNexusEngine::GetConnection(const std::string& connectionId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_connections.find(connectionId);
    if (it != s_connections.end()) return it->second;
    return NexusConnection{};
}

std::vector<NexusConnection> AstralNexusEngine::GetAllConnections() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<NexusConnection> result;
    for (const auto& [id, connection] : s_connections) {
        result.push_back(connection);
    }
    return result;
}

std::vector<NexusConnection> AstralNexusEngine::GetConnectionsByNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<NexusConnection> result;
    for (const auto& [id, connection] : s_connections) {
        if (connection.sourceId == nodeId || connection.destinationId == nodeId) {
            result.push_back(connection);
        }
    }
    return result;
}

float AstralNexusEngine::CalculateNexusConnectivity() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_connections.empty()) return 1.0f;
    float totalStrength = 0.0f;
    for (const auto& [id, connection] : s_connections) {
        totalStrength += connection.strength;
    }
    return totalStrength / s_connections.size();
}

float AstralNexusEngine::CalculateAverageThroughput() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_portals.empty()) return 0.0f;
    float totalThroughput = 0.0f;
    int activeCount = 0;
    for (const auto& [id, portal] : s_portals) {
        if (portal.active) {
            totalThroughput += portal.throughput;
            activeCount++;
        }
    }
    return activeCount > 0 ? totalThroughput / activeCount : 0.0f;
}

nlohmann::json AstralNexusEngine::GetNexusMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json metrics;
    metrics["portalCount"] = s_portals.size();
    metrics["activePortalCount"] = GetActivePortals().size();
    metrics["gatewayCount"] = s_gateways.size();
    metrics["bridgeCount"] = s_bridges.size();
    metrics["conduitCount"] = s_conduits.size();
    metrics["connectionCount"] = s_connections.size();
    metrics["nexusConnectivity"] = CalculateNexusConnectivity();
    metrics["averageThroughput"] = CalculateAverageThroughput();
    metrics["tickCount"] = s_tickCount;
    return metrics;
}

nlohmann::json AstralNexusEngine::GenerateNexusReport() {
    nlohmann::json report;
    report["metrics"] = GetNexusMetrics();
    report["activePortals"] = nlohmann::json::array();
    report["establishedConnections"] = nlohmann::json::array();
    report["bridgeStatus"] = nlohmann::json::array();
    
    for (const auto& portal : GetActivePortals()) {
        nlohmann::json p;
        p["id"] = portal.portalId;
        p["name"] = portal.name;
        p["source"] = portal.sourceUniverse;
        p["destination"] = portal.destinationUniverse;
        p["stability"] = portal.stability;
        report["activePortals"].push_back(p);
    }
    
    for (const auto& connection : GetAllConnections()) {
        nlohmann::json c;
        c["id"] = connection.connectionId;
        c["type"] = connection.connectionType;
        c["strength"] = connection.strength;
        c["reliability"] = connection.reliability;
        report["establishedConnections"].push_back(c);
    }
    
    return report;
}

void AstralNexusEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_tickCount++;
    
    for (auto& [id, portal] : s_portals) {
        if (portal.active) {
            portal.stability *= 0.9999f;
            portal.stability += 0.0001f;
        }
    }
    
    for (auto& [id, bridge] : s_bridges) {
        bridge.structuralIntegrity *= 0.9999f;
        bridge.structuralIntegrity += 0.0001f;
        bridge.trafficLoad *= 0.999f;
    }
    
    for (auto& [id, conduit] : s_conduits) {
        conduit.efficiency *= 0.9999f;
        conduit.efficiency += 0.0001f;
    }
}

bool AstralNexusEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

} // namespace Astral
