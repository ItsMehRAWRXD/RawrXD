/**
 * NodeDiscovery.cpp
 *
 * Phase D.3 Batch 1/5: Distributed Node Discovery & Communication
 */

#include "NodeDiscovery.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
    #include <iphlpapi.h>
    #pragma comment(lib, "iphlpapi.lib")
#else
    #include <ifaddrs.h>
    #include <netdb.h>
#endif

namespace Distributed {

// ============================================================================
// NodeInfo Implementation
// ============================================================================

std::string NodeInfo::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"nodeId\":\"" << nodeId << "\",";
    json << "\"address\":\"" << address << "\",";
    json << "\"communicationPort\":" << communicationPort << ",";
    json << "\"region\":\"" << region << "\",";
    json << "\"zone\":\"" << zone << "\",";
    json << "\"capacityScore\":" << capacityScore << ",";
    json << "\"currentLoad\":" << currentLoad << ",";
    json << "\"isLeader\":" << (isLeader ? "true" : "false") << ",";
    json << "\"term\":" << term << ",";
    json << "\"capabilities\":[";
    for (size_t i = 0; i < capabilities.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << capabilities[i] << "\"";
    }
    json << "]}";
    return json.str();
}

std::optional<NodeInfo> NodeInfo::FromJson(const std::string& json) {
    // Simplified JSON parsing - production would use proper JSON library
    NodeInfo info;
    // Parse fields from JSON string
    // This is a stub implementation
    return info;
}

// ============================================================================
// DiscoveryConfig Implementation
// ============================================================================

bool DiscoveryConfig::Validate() const {
    if (nodeId.empty()) return false;
    if (discoveryPort <= 0 || discoveryPort > 65535) return false;
    if (communicationPort <= 0 || communicationPort > 65535) return false;
    if (!IsValidMulticastAddress(multicastGroup)) return false;
    return true;
}

std::string DiscoveryConfig::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"nodeId\":\"" << nodeId << "\",";
    json << "\"bindAddress\":\"" << bindAddress << "\",";
    json << "\"discoveryPort\":" << discoveryPort << ",";
    json << "\"communicationPort\":" << communicationPort << ",";
    json << "\"multicastGroup\":\"" << multicastGroup << "\",";
    json << "\"region\":\"" << region << "\",";
    json << "\"zone\":\"" << zone << "\",";
    json << "\"capacityScore\":" << capacityScore << ",";
    json << "\"enableEncryption\":" << (enableEncryption ? "true" : "false");
    json << "}";
    return json.str();
}

// ============================================================================
// NodeRegistry Implementation
// ============================================================================

NodeRegistry::NodeRegistry() = default;
NodeRegistry::~NodeRegistry() = default;

void NodeRegistry::RegisterNode(const NodeInfo& node) {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_[node.nodeId] = node;
}

void NodeRegistry::UpdateNode(const NodeInfo& node) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(node.nodeId);
    if (it != nodes_.end()) {
        it->second = node;
    } else {
        nodes_[node.nodeId] = node;
    }
}

void NodeRegistry::RemoveNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_.erase(nodeId);
}

std::optional<NodeInfo> NodeRegistry::GetNode(const std::string& nodeId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(nodeId);
    if (it != nodes_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<NodeInfo> NodeRegistry::GetAllNodes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<NodeInfo> result;
    for (const auto& [id, node] : nodes_) {
        result.push_back(node);
    }
    return result;
}

std::vector<NodeInfo> NodeRegistry::GetAliveNodes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<NodeInfo> result;
    for (const auto& [id, node] : nodes_) {
        if (node.IsAlive()) {
            result.push_back(node);
        }
    }
    return result;
}

std::vector<NodeInfo> NodeRegistry::GetNodesByRegion(const std::string& region) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<NodeInfo> result;
    for (const auto& [id, node] : nodes_) {
        if (node.region == region && node.IsAlive()) {
            result.push_back(node);
        }
    }
    return result;
}

std::vector<NodeInfo> NodeRegistry::GetNodesByCapability(const std::string& capability) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<NodeInfo> result;
    for (const auto& [id, node] : nodes_) {
        if (node.IsAlive()) {
            for (const auto& cap : node.capabilities) {
                if (cap == capability) {
                    result.push_back(node);
                    break;
                }
            }
        }
    }
    return result;
}

std::optional<NodeInfo> NodeRegistry::GetLeader() const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [id, node] : nodes_) {
        if (node.isLeader && node.IsAlive()) {
            return node;
        }
    }
    return std::nullopt;
}

size_t NodeRegistry::GetNodeCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return nodes_.size();
}

size_t NodeRegistry::GetAliveNodeCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [id, node] : nodes_) {
        if (node.IsAlive()) {
            count++;
        }
    }
    return count;
}

bool NodeRegistry::HasQuorum(size_t totalNodes) const {
    return GetAliveNodeCount() >= (totalNodes / 2 + 1);
}

void NodeRegistry::RemoveStaleNodes(std::chrono::milliseconds timeout) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    for (auto it = nodes_.begin(); it != nodes_.end();) {
        if ((now - it->second.lastSeen) > timeout) {
            it = nodes_.erase(it);
        } else {
            ++it;
        }
    }
}

void NodeRegistry::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_.clear();
}

// ============================================================================
// DiscoveryProtocol Implementation
// ============================================================================

DiscoveryProtocol::DiscoveryProtocol() = default;

DiscoveryProtocol::~DiscoveryProtocol() {
    Shutdown();
}

bool DiscoveryProtocol::Initialize(const DiscoveryConfig& config) {
    if (!config.Validate()) {
        std::cerr << "[Discovery] Invalid configuration\n";
        return false;
    }
    
    config_ = config;
    
    // Initialize platform-specific networking
    #ifdef _WIN32
    if (!wsaInitialized_) {
        if (WSAStartup(MAKEWORD(2, 2), &wsaData_) != 0) {
            std::cerr << "[Discovery] WSAStartup failed\n";
            return false;
        }
        wsaInitialized_ = true;
    }
    #endif
    
    // Setup local node info
    localNode_.nodeId = config_.nodeId.empty() ? GenerateNodeId() : config_.nodeId;
    localNode_.address = config_.bindAddress.empty() ? GetLocalIpAddress() : config_.bindAddress;
    localNode_.communicationPort = config_.communicationPort;
    localNode_.region = config_.region;
    localNode_.zone = config_.zone;
    localNode_.capacityScore = config_.capacityScore;
    localNode_.capabilities = config_.capabilities;
    localNode_.isLeader = false;
    localNode_.term = 0;
    localNode_.joinedAt = std::chrono::steady_clock::now();
    localNode_.lastSeen = localNode_.joinedAt;
    
    // Create socket
    if (!CreateSocket()) {
        return false;
    }
    
    // Join multicast group
    if (!JoinMulticastGroup()) {
        CloseSocket();
        return false;
    }
    
    // Start threads
    running_ = true;
    discoveryThread_ = std::thread(&DiscoveryProtocol::DiscoveryLoop, this);
    receiveThread_ = std::thread(&DiscoveryProtocol::ReceiveLoop, this);
    cleanupThread_ = std::thread(&DiscoveryProtocol::CleanupLoop, this);
    
    std::cout << "[Discovery] Initialized node " << localNode_.nodeId << "\n";
    std::cout << "[Discovery] Listening on " << config_.multicastGroup << ":" << config_.discoveryPort << "\n";
    
    return true;
}

void DiscoveryProtocol::Shutdown() {
    if (!running_.load()) {
        return;
    }
    
    running_ = false;
    
    // Send leave announcement
    AnnouncePresence();
    
    // Join threads
    if (discoveryThread_.joinable()) {
        discoveryThread_.join();
    }
    if (receiveThread_.joinable()) {
        receiveThread_.join();
    }
    if (cleanupThread_.joinable()) {
        cleanupThread_.join();
    }
    
    // Leave multicast group and close socket
    LeaveMulticastGroup();
    CloseSocket();
    
    // Cleanup platform-specific
    #ifdef _WIN32
    if (wsaInitialized_) {
        WSACleanup();
        wsaInitialized_ = false;
    }
    #endif
    
    std::cout << "[Discovery] Shutdown complete\n";
}

bool DiscoveryProtocol::JoinCluster() {
    // Announce presence to cluster
    AnnouncePresence();
    
    // Request node list from existing nodes
    RequestNodeList();
    
    return true;
}

bool DiscoveryProtocol::LeaveCluster() {
    // Send leave message
    DiscoveryMessage msg;
    msg.type = DiscoveryMessageType::LEAVE;
    msg.senderId = localNode_.nodeId;
    msg.nodeInfo = localNode_;
    msg.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    auto data = msg.Serialize();
    sendto(socket_, reinterpret_cast<const char*>(data.data()), data.size(), 0,
           reinterpret_cast<const sockaddr*>(&multicastAddr_), sizeof(multicastAddr_));
    
    return true;
}

void DiscoveryProtocol::AnnouncePresence() {
    DiscoveryMessage msg;
    msg.type = DiscoveryMessageType::ANNOUNCE;
    msg.senderId = localNode_.nodeId;
    msg.nodeInfo = localNode_;
    msg.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    auto data = msg.Serialize();
    int sent = sendto(socket_, reinterpret_cast<const char*>(data.data()), data.size(), 0,
                      reinterpret_cast<const sockaddr*>(&multicastAddr_), sizeof(multicastAddr_));
    
    if (sent > 0) {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.announcementsSent++;
        stats_.bytesSent += sent;
    }
}

void DiscoveryProtocol::RequestNodeList() {
    DiscoveryMessage msg;
    msg.type = DiscoveryMessageType::DISCOVERY;
    msg.senderId = localNode_.nodeId;
    msg.nodeInfo = localNode_;
    msg.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    auto data = msg.Serialize();
    sendto(socket_, reinterpret_cast<const char*>(data.data()), data.size(), 0,
           reinterpret_cast<const sockaddr*>(&multicastAddr_), sizeof(multicastAddr_));
}

void DiscoveryProtocol::SetCallback(DiscoveryCallback callback) {
    callback_ = callback;
}

DiscoveryProtocol::Stats DiscoveryProtocol::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void DiscoveryProtocol::ResetStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_ = Stats{};
}

// ============================================================================
// Private Methods
// ============================================================================

bool DiscoveryProtocol::CreateSocket() {
    socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ < 0) {
        std::cerr << "[Discovery] Failed to create socket\n";
        return false;
    }
    
    // Enable address reuse
    int reuse = 1;
    if (setsockopt(socket_, SOL_SOCKET, SO_REUSEADDR, 
                   reinterpret_cast<const char*>(&reuse), sizeof(reuse)) < 0) {
        std::cerr << "[Discovery] Failed to set SO_REUSEADDR\n";
        CloseSocket();
        return false;
    }
    
    // Bind to port
    bindAddr_.sin_family = AF_INET;
    bindAddr_.sin_port = htons(config_.discoveryPort);
    bindAddr_.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(socket_, reinterpret_cast<const sockaddr*>(&bindAddr_), sizeof(bindAddr_)) < 0) {
        std::cerr << "[Discovery] Failed to bind socket\n";
        CloseSocket();
        return false;
    }
    
    // Setup multicast address
    multicastAddr_.sin_family = AF_INET;
    multicastAddr_.sin_port = htons(config_.discoveryPort);
    inet_pton(AF_INET, config_.multicastGroup.c_str(), &multicastAddr_.sin_addr);
    
    return true;
}

void DiscoveryProtocol::CloseSocket() {
    if (socket_ >= 0) {
        #ifdef _WIN32
        closesocket(socket_);
        #else
        close(socket_);
        #endif
        socket_ = -1;
    }
}

bool DiscoveryProtocol::JoinMulticastGroup() {
    ip_mreq mreq;
    inet_pton(AF_INET, config_.multicastGroup.c_str(), &mreq.imr_multiaddr);
    mreq.imr_interface.s_addr = INADDR_ANY;
    
    if (setsockopt(socket_, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   reinterpret_cast<const char*>(&mreq), sizeof(mreq)) < 0) {
        std::cerr << "[Discovery] Failed to join multicast group\n";
        return false;
    }
    
    return true;
}

bool DiscoveryProtocol::LeaveMulticastGroup() {
    ip_mreq mreq;
    inet_pton(AF_INET, config_.multicastGroup.c_str(), &mreq.imr_multiaddr);
    mreq.imr_interface.s_addr = INADDR_ANY;
    
    setsockopt(socket_, IPPROTO_IP, IP_DROP_MEMBERSHIP,
               reinterpret_cast<const char*>(&mreq), sizeof(mreq));
    
    return true;
}

void DiscoveryProtocol::DiscoveryLoop() {
    while (running_.load()) {
        AnnouncePresence();
        std::this_thread::sleep_for(config_.discoveryInterval);
    }
}

void DiscoveryProtocol::ReceiveLoop() {
    char buffer[MAX_DISCOVERY_PACKET_SIZE];
    sockaddr_in fromAddr;
    socklen_t fromLen = sizeof(fromAddr);
    
    while (running_.load()) {
        #ifdef _WIN32
        int received = recvfrom(socket_, buffer, sizeof(buffer), 0,
                                reinterpret_cast<sockaddr*>(&fromAddr), &fromLen);
        #else
        ssize_t received = recvfrom(socket_, buffer, sizeof(buffer), 0,
                                    reinterpret_cast<sockaddr*>(&fromAddr), &fromLen);
        #endif
        
        if (received > 0) {
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.announcementsReceived++;
            stats_.bytesReceived += received;
            
            ProcessIncomingPacket(buffer, received, fromAddr);
        }
    }
}

void DiscoveryProtocol::CleanupLoop() {
    while (running_.load()) {
        std::this_thread::sleep_for(config_.nodeTimeout / 2);
        
        auto staleNodes = registry_.GetAllNodes();
        for (const auto& node : staleNodes) {
            if (!node.IsAlive() && node.nodeId != localNode_.nodeId) {
                registry_.RemoveNode(node.nodeId);
                
                if (callback_) {
                    DiscoveryEvent event;
                    event.type = DiscoveryEventType::NODE_LEFT;
                    event.node = node;
                    event.timestamp = std::chrono::steady_clock::now();
                    event.reason = "Timeout";
                    callback_(event);
                }
                
                std::lock_guard<std::mutex> lock(statsMutex_);
                stats_.nodesLost++;
            }
        }
    }
}

void DiscoveryProtocol::ProcessIncomingPacket(const char* data, size_t len, 
                                               const sockaddr_in& fromAddr) {
    std::vector<uint8_t> packet(data, data + len);
    auto msg = DiscoveryMessage::Deserialize(packet);
    
    if (!msg.has_value()) {
        return;
    }
    
    // Ignore messages from self
    if (msg->senderId == localNode_.nodeId) {
        return;
    }
    
    // Update node info
    NodeInfo node = msg->nodeInfo;
    node.lastSeen = std::chrono::steady_clock::now();
    
    bool isNew = !registry_.GetNode(node.nodeId).has_value();
    registry_.UpdateNode(node);
    
    // Handle message type
    switch (msg->type) {
        case DiscoveryMessageType::ANNOUNCE:
            if (isNew) {
                if (callback_) {
                    DiscoveryEvent event;
                    event.type = DiscoveryEventType::NODE_JOINED;
                    event.node = node;
                    event.timestamp = std::chrono::steady_clock::now();
                    callback_(event);
                }
                
                std::lock_guard<std::mutex> lock(statsMutex_);
                stats_.nodesDiscovered++;
            }
            break;
            
        case DiscoveryMessageType::DISCOVERY:
            // Send response with our node info
            {
                DiscoveryMessage response;
                response.type = DiscoveryMessageType::RESPONSE;
                response.senderId = localNode_.nodeId;
                response.nodeInfo = localNode_;
                response.knownNodes = registry_.GetAllNodes();
                response.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                
                auto respData = response.Serialize();
                sendto(socket_, reinterpret_cast<const char*>(respData.data()), respData.size(), 0,
                       reinterpret_cast<const sockaddr*>(&fromAddr), sizeof(fromAddr));
            }
            break;
            
        case DiscoveryMessageType::RESPONSE:
            // Add discovered nodes
            for (const auto& discoveredNode : msg->knownNodes) {
                if (discoveredNode.nodeId != localNode_.nodeId) {
                    if (!registry_.GetNode(discoveredNode.nodeId).has_value()) {
                        registry_.RegisterNode(discoveredNode);
                        
                        if (callback_) {
                            DiscoveryEvent event;
                            event.type = DiscoveryEventType::NODE_JOINED;
                            event.node = discoveredNode;
                            event.timestamp = std::chrono::steady_clock::now();
                            callback_(event);
                        }
                    }
                }
            }
            break;
            
        case DiscoveryMessageType::LEAVE:
            registry_.RemoveNode(node.nodeId);
            
            if (callback_) {
                DiscoveryEvent event;
                event.type = DiscoveryEventType::NODE_LEFT;
                event.node = node;
                event.timestamp = std::chrono::steady_clock::now();
                event.reason = "Graceful departure";
                callback_(event);
            }
            break;
            
        default:
            break;
    }
}

std::string DiscoveryProtocol::GenerateNodeId() const {
    return GenerateNodeId();
}

uint64_t DiscoveryProtocol::CalculateCapacityScore() const {
    // Calculate based on CPU cores, memory, GPU availability
    // This is a simplified implementation
    return config_.capacityScore;
}

// ============================================================================
// DiscoveryMessage Implementation
// ============================================================================

std::vector<uint8_t> DiscoveryMessage::Serialize() const {
    // Simplified serialization - production would use protobuf or similar
    std::string json = "{";
    json += "\"type\":" + std::to_string(static_cast<int>(type)) + ",";
    json += "\"senderId\":\"" + senderId + "\",";
    json += "\"nodeInfo\":" + nodeInfo.ToJson() + ",";
    json += "\"timestamp\":" + std::to_string(timestamp);
    json += "}";
    
    return std::vector<uint8_t>(json.begin(), json.end());
}

std::optional<DiscoveryMessage> DiscoveryMessage::Deserialize(const std::vector<uint8_t>& data) {
    // Simplified deserialization - production would use proper JSON parser
    DiscoveryMessage msg;
    // Parse JSON and populate fields
    // This is a stub implementation
    return msg;
}

// ============================================================================
// Utility Functions
// ============================================================================

std::string GenerateNodeId() {
    // Generate UUID-like node ID
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    const char* hex = "0123456789abcdef";
    std::string uuid;
    uuid.reserve(36);
    
    for (int i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            uuid += '-';
        } else {
            uuid += hex[dis(gen)];
        }
    }
    
    return "node-" + uuid;
}

std::string GetLocalIpAddress() {
    // Get first non-loopback IP address
    #ifdef _WIN32
    // Windows implementation
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        struct hostent* host = gethostbyname(hostname);
        if (host && host->h_addr_list[0]) {
            struct in_addr addr;
            memcpy(&addr, host->h_addr_list[0], sizeof(addr));
            return inet_ntoa(addr);
        }
    }
    #else
    // Unix implementation
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == 0) {
        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
                std::string addr = inet_ntoa(sin->sin_addr);
                if (addr != "127.0.0.1") {
                    freeifaddrs(ifaddr);
                    return addr;
                }
            }
        }
        freeifaddrs(ifaddr);
    }
    #endif
    
    return "127.0.0.1";
}

bool IsValidMulticastAddress(const std::string& addr) {
    // Check if address is in valid multicast range (224.0.0.0 - 239.255.255.255)
    struct in_addr ip;
    if (inet_pton(AF_INET, addr.c_str(), &ip) != 1) {
        return false;
    }
    
    uint32_t ipAddr = ntohl(ip.s_addr);
    return (ipAddr >= 0xE0000000 && ipAddr <= 0xEFFFFFFF);
}

} // namespace Distributed
