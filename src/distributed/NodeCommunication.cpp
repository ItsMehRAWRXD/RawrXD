/**
 * NodeCommunication.cpp
 *
 * Phase D.3 Batch 1/5: Distributed Node Discovery & Communication
 */

#include "NodeCommunication.hpp"
#include <iostream>
#include <cstring>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
#endif

namespace Distributed {

// ============================================================================
// Message Implementation
// ============================================================================

std::vector<uint8_t> Message::Serialize() const {
    std::vector<uint8_t> data;
    
    // Serialize header
    const uint8_t* headerBytes = reinterpret_cast<const uint8_t*>(&header);
    data.insert(data.end(), headerBytes, headerBytes + sizeof(header));
    
    // Serialize payload
    data.insert(data.end(), payload.begin(), payload.end());
    
    return data;
}

std::optional<Message> Message::Deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(MessageHeader)) {
        return std::nullopt;
    }
    
    Message msg;
    
    // Deserialize header
    std::memcpy(&msg.header, data.data(), sizeof(MessageHeader));
    
    // Validate magic and version
    if (msg.header.magic != MessageHeader::MAGIC || 
        msg.header.version != MessageHeader::VERSION) {
        return std::nullopt;
    }
    
    // Deserialize payload
    if (data.size() > sizeof(MessageHeader)) {
        msg.payload.assign(data.begin() + sizeof(MessageHeader), data.end());
    }
    
    return msg;
}

// ============================================================================
// NodeConnection Implementation
// ============================================================================

NodeConnection::NodeConnection() = default;

NodeConnection::~NodeConnection() {
    Disconnect();
}

bool NodeConnection::Connect(const NodeInfo& node) {
    if (connected_.load()) {
        return true; // Already connected
    }
    
    nodeInfo_ = node;
    
    // Create socket
    socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ < 0) {
        std::cerr << "[Communication] Failed to create socket\n";
        return false;
    }
    
    // Set socket options
    int flag = 1;
    setsockopt(socket_, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&flag), sizeof(flag));
    
    // Connect to node
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(node.communicationPort);
    inet_pton(AF_INET, node.address.c_str(), &addr.sin_addr);
    
    if (connect(socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "[Communication] Failed to connect to " << node.nodeId << "\n";
        CloseSocket();
        return false;
    }
    
    // Send handshake
    Message handshake;
    handshake.header.magic = MessageHeader::MAGIC;
    handshake.header.version = MessageHeader::VERSION;
    handshake.header.type = MessageType::HANDSHAKE;
    handshake.header.payloadLength = 0;
    handshake.header.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    handshake.header.sequenceNumber = 0;
    std::strncpy(handshake.header.senderId, "local", sizeof(handshake.header.senderId));
    std::strncpy(handshake.header.targetId, node.nodeId.c_str(), sizeof(handshake.header.targetId));
    
    if (!SendMessage(handshake)) {
        CloseSocket();
        return false;
    }
    
    connected_ = true;
    running_ = true;
    receiveThread_ = std::thread(&NodeConnection::ReceiveLoop, this);
    
    std::cout << "[Communication] Connected to " << node.nodeId << "\n";
    return true;
}

void NodeConnection::Disconnect() {
    if (!connected_.load()) {
        return;
    }
    
    // Send disconnect message
    Message disconnect;
    disconnect.header.magic = MessageHeader::MAGIC;
    disconnect.header.version = MessageHeader::VERSION;
    disconnect.header.type = MessageType::DISCONNECT;
    disconnect.header.payloadLength = 0;
    SendMessage(disconnect);
    
    running_ = false;
    
    if (receiveThread_.joinable()) {
        receiveThread_.join();
    }
    
    CloseSocket();
    connected_ = false;
    
    // Clear pending RPCs
    std::lock_guard<std::mutex> lock(rpcMutex_);
    for (auto& [id, promise] : rpcPromises_) {
        RpcResponse errorResponse;
        errorResponse.requestId = id;
        errorResponse.success = false;
        errorResponse.errorMessage = "Connection closed";
        promise.set_value(errorResponse);
    }
    rpcPromises_.clear();
}

bool NodeConnection::SendMessage(const Message& msg) {
    if (!connected_.load()) {
        return false;
    }
    
    auto data = msg.Serialize();
    
    // Send length first (4 bytes)
    uint32_t length = static_cast<uint32_t>(data.size());
    if (!SendRaw(&length, sizeof(length))) {
        return false;
    }
    
    // Send data
    if (!SendRaw(data.data(), data.size())) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_.messagesSent++;
    stats_.bytesSent += data.size();
    
    return true;
}

bool NodeConnection::SendRpcRequest(const RpcRequest& request, RpcResponse& response) {
    if (!connected_.load()) {
        return false;
    }
    
    // Create RPC message
    Message msg;
    msg.header.magic = MessageHeader::MAGIC;
    msg.header.version = MessageHeader::VERSION;
    msg.header.type = MessageType::RPC_REQUEST;
    msg.header.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    msg.header.sequenceNumber = request.requestId;
    
    // Serialize RPC request
    std::string rpcJson = "{\"method\":\"" + request.method + "\",\"requestId\":" + 
                          std::to_string(request.requestId) + "}";
    msg.payload.assign(rpcJson.begin(), rpcJson.end());
    msg.header.payloadLength = static_cast<uint32_t>(msg.payload.size());
    
    // Create promise for async response
    std::promise<RpcResponse> promise;
    auto future = promise.get_future();
    
    {
        std::lock_guard<std::mutex> lock(rpcMutex_);
        rpcPromises_[request.requestId] = std::move(promise);
    }
    
    // Send request
    if (!SendMessage(msg)) {
        std::lock_guard<std::mutex> lock(rpcMutex_);
        rpcPromises_.erase(request.requestId);
        return false;
    }
    
    // Wait for response
    auto status = future.wait_for(request.timeout);
    if (status == std::future_status::timeout) {
        std::lock_guard<std::mutex> lock(rpcMutex_);
        rpcPromises_.erase(request.requestId);
        
        stats_.rpcFailures++;
        return false;
    }
    
    response = future.get();
    
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_.rpcCalls++;
    
    return response.success;
}

void NodeConnection::SubscribeToEvents(const std::string& eventType) {
    std::lock_guard<std::mutex> lock(eventMutex_);
    eventSubscriptions_.insert(eventType);
    
    // Send subscribe message
    Message msg;
    msg.header.magic = MessageHeader::MAGIC;
    msg.header.version = MessageHeader::VERSION;
    msg.header.type = MessageType::EVENT_SUBSCRIBE;
    msg.payload.assign(eventType.begin(), eventType.end());
    msg.header.payloadLength = static_cast<uint32_t>(msg.payload.size());
    
    SendMessage(msg);
}

void NodeConnection::UnsubscribeFromEvents(const std::string& eventType) {
    std::lock_guard<std::mutex> lock(eventMutex_);
    eventSubscriptions_.erase(eventType);
    
    // Send unsubscribe message
    Message msg;
    msg.header.magic = MessageHeader::MAGIC;
    msg.header.version = MessageHeader::VERSION;
    msg.header.type = MessageType::EVENT_UNSUBSCRIBE;
    msg.payload.assign(eventType.begin(), eventType.end());
    msg.header.payloadLength = static_cast<uint32_t>(msg.payload.size());
    
    SendMessage(msg);
}

NodeConnection::Stats NodeConnection::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void NodeConnection::ReceiveLoop() {
    while (running_.load()) {
        // Receive message length
        uint32_t length;
        if (!ReceiveRaw(&length, sizeof(length))) {
            if (running_.load()) {
                std::cerr << "[Communication] Failed to receive message length\n";
            }
            break;
        }
        
        if (length > 1024 * 1024) { // Max 1MB
            std::cerr << "[Communication] Message too large: " << length << "\n";
            break;
        }
        
        // Receive message data
        std::vector<uint8_t> data(length);
        if (!ReceiveRaw(data.data(), length)) {
            std::cerr << "[Communication] Failed to receive message data\n";
            break;
        }
        
        // Deserialize and process
        auto msg = Message::Deserialize(data);
        if (msg.has_value()) {
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.messagesReceived++;
            stats_.bytesReceived += length;
            
            ProcessMessage(msg.value());
        }
    }
}

bool NodeConnection::SendRaw(const void* data, size_t len) {
    const char* ptr = static_cast<const char*>(data);
    size_t sent = 0;
    
    while (sent < len) {
        int result = send(socket_, ptr + sent, static_cast<int>(len - sent), 0);
        if (result < 0) {
            return false;
        }
        sent += result;
    }
    
    return true;
}

bool NodeConnection::ReceiveRaw(void* buffer, size_t len) {
    char* ptr = static_cast<char*>(buffer);
    size_t received = 0;
    
    while (received < len) {
        int result = recv(socket_, ptr + received, static_cast<int>(len - received), 0);
        if (result <= 0) {
            return false;
        }
        received += result;
    }
    
    return true;
}

void NodeConnection::ProcessMessage(const Message& msg) {
    switch (msg.header.type) {
        case MessageType::RPC_RESPONSE:
        case MessageType::RPC_ERROR: {
            uint64_t requestId = msg.header.sequenceNumber;
            
            std::lock_guard<std::mutex> lock(rpcMutex_);
            auto it = rpcPromises_.find(requestId);
            if (it != rpcPromises_.end()) {
                RpcResponse response;
                response.requestId = requestId;
                response.success = (msg.header.type == MessageType::RPC_RESPONSE);
                response.result = msg.payload;
                
                if (!response.success) {
                    response.errorMessage.assign(msg.payload.begin(), msg.payload.end());
                }
                
                it->second.set_value(response);
                rpcPromises_.erase(it);
            }
            break;
        }
        
        case MessageType::EVENT_PUBLISH: {
            // Handle event
            break;
        }
        
        case MessageType::HEARTBEAT: {
            // Update last seen
            break;
        }
        
        default:
            break;
    }
}

void NodeConnection::CloseSocket() {
    if (socket_ >= 0) {
        #ifdef _WIN32
        closesocket(socket_);
        #else
        close(socket_);
        #endif
        socket_ = -1;
    }
}

// ============================================================================
// MessageBus Implementation
// ============================================================================

MessageBus::MessageBus() = default;

MessageBus::~MessageBus() {
    Shutdown();
}

bool MessageBus::Initialize(const DiscoveryConfig& config) {
    config_ = config;
    running_ = true;
    senderThread_ = std::thread(&MessageBus::SenderLoop, this);
    
    std::cout << "[MessageBus] Initialized\n";
    return true;
}

void MessageBus::Shutdown() {
    running_ = false;
    queueCv_.notify_all();
    
    if (senderThread_.joinable()) {
        senderThread_.join();
    }
    
    DisconnectAll();
    
    std::cout << "[MessageBus] Shutdown complete\n";
}

bool MessageBus::ConnectToNode(const NodeInfo& node) {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    if (connections_.find(node.nodeId) != connections_.end()) {
        return true; // Already connected
    }
    
    auto connection = std::make_unique<NodeConnection>();
    if (!connection->Connect(node)) {
        return false;
    }
    
    connections_[node.nodeId] = std::move(connection);
    
    std::lock_guard<std::mutex> statsLock(statsMutex_);
    stats_.activeConnections = connections_.size();
    
    return true;
}

void MessageBus::DisconnectFromNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    auto it = connections_.find(nodeId);
    if (it != connections_.end()) {
        it->second->Disconnect();
        connections_.erase(it);
    }
    
    std::lock_guard<std::mutex> statsLock(statsMutex_);
    stats_.activeConnections = connections_.size();
}

void MessageBus::DisconnectAll() {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    for (auto& [id, conn] : connections_) {
        conn->Disconnect();
    }
    connections_.clear();
    
    std::lock_guard<std::mutex> statsLock(statsMutex_);
    stats_.activeConnections = 0;
}

bool MessageBus::SendToNode(const std::string& nodeId, const Message& msg) {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    auto it = connections_.find(nodeId);
    if (it == connections_.end()) {
        std::lock_guard<std::mutex> statsLock(statsMutex_);
        stats_.failedSends++;
        return false;
    }
    
    bool success = it->second->SendMessage(msg);
    
    if (success) {
        std::lock_guard<std::mutex> statsLock(statsMutex_);
        stats_.totalMessagesSent++;
        stats_.totalBytesSent += msg.payload.size() + sizeof(msg.header);
    } else {
        std::lock_guard<std::mutex> statsLock(statsMutex_);
        stats_.failedSends++;
    }
    
    return success;
}

bool MessageBus::Broadcast(const Message& msg) {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    bool allSuccess = true;
    for (auto& [id, conn] : connections_) {
        if (!conn->SendMessage(msg)) {
            allSuccess = false;
        }
    }
    
    std::lock_guard<std::mutex> statsLock(statsMutex_);
    stats_.totalMessagesSent += connections_.size();
    
    return allSuccess;
}

bool MessageBus::RpcCall(const std::string& nodeId, const RpcRequest& request, RpcResponse& response) {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    auto it = connections_.find(nodeId);
    if (it == connections_.end()) {
        std::lock_guard<std::mutex> statsLock(statsMutex_);
        stats_.failedRpcs++;
        return false;
    }
    
    bool success = it->second->SendRpcRequest(request, response);
    
    if (!success) {
        std::lock_guard<std::mutex> statsLock(statsMutex_);
        stats_.failedRpcs++;
    }
    
    return success;
}

void MessageBus::PublishEvent(const std::string& eventType, const std::vector<uint8_t>& data) {
    Message msg;
    msg.header.magic = MessageHeader::MAGIC;
    msg.header.version = MessageHeader::VERSION;
    msg.header.type = MessageType::EVENT_PUBLISH;
    msg.header.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    // Prepend event type to payload
    std::string typeHeader = eventType + ":";
    msg.payload.reserve(typeHeader.size() + data.size());
    msg.payload.insert(msg.payload.end(), typeHeader.begin(), typeHeader.end());
    msg.payload.insert(msg.payload.end(), data.begin(), data.end());
    msg.header.payloadLength = static_cast<uint32_t>(msg.payload.size());
    
    Broadcast(msg);
}

void MessageBus::SubscribeToEvent(const std::string& eventType, 
                                   std::function<void(const std::string&, const std::vector<uint8_t>&)> handler) {
    std::lock_guard<std::mutex> lock(handlersMutex_);
    eventHandlers_[eventType].push_back(handler);
}

void MessageBus::UnsubscribeFromEvent(const std::string& eventType) {
    std::lock_guard<std::mutex> lock(handlersMutex_);
    eventHandlers_.erase(eventType);
}

std::vector<std::string> MessageBus::GetConnectedNodes() const {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    std::vector<std::string> nodes;
    for (const auto& [id, conn] : connections_) {
        if (conn->IsConnected()) {
            nodes.push_back(id);
        }
    }
    return nodes;
}

bool MessageBus::IsConnectedTo(const std::string& nodeId) const {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    auto it = connections_.find(nodeId);
    return it != connections_.end() && it->second->IsConnected();
}

size_t MessageBus::GetConnectionCount() const {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    return connections_.size();
}

MessageBus::BusStats MessageBus::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void MessageBus::SenderLoop() {
    while (running_.load()) {
        std::unique_lock<std::mutex> lock(queueMutex_);
        queueCv_.wait(lock, [this] { return !messageQueue_.empty() || !running_.load(); });
        
        while (!messageQueue_.empty()) {
            auto [nodeId, msg] = messageQueue_.front();
            messageQueue_.pop();
            lock.unlock();
            
            SendToNode(nodeId, msg);
            
            lock.lock();
        }
    }
}

void MessageBus::CleanupConnections() {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    for (auto it = connections_.begin(); it != connections_.end();) {
        if (!it->second->IsConnected()) {
            it = connections_.erase(it);
        } else {
            ++it;
        }
    }
}

// ============================================================================
// HeartbeatMonitor Implementation
// ============================================================================

HeartbeatMonitor::HeartbeatMonitor() = default;

HeartbeatMonitor::~HeartbeatMonitor() {
    Shutdown();
}

bool HeartbeatMonitor::Initialize(std::chrono::milliseconds interval, std::chrono::milliseconds timeout) {
    interval_ = interval;
    timeout_ = timeout;
    running_ = true;
    
    monitorThread_ = std::thread(&HeartbeatMonitor::MonitorLoop, this);
    
    std::cout << "[HeartbeatMonitor] Initialized (interval: " << interval_.count() 
              << "ms, timeout: " << timeout_.count() << "ms)\n";
    return true;
}

void HeartbeatMonitor::Shutdown() {
    running_ = false;
    
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
}

void HeartbeatMonitor::RegisterNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    NodeHeartbeat hb;
    hb.lastSeen = std::chrono::steady_clock::now();
    hb.wasAlive = true;
    
    nodes_[nodeId] = hb;
}

void HeartbeatMonitor::UnregisterNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    nodes_.erase(nodeId);
}

void HeartbeatMonitor::RecordHeartbeat(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    auto it = nodes_.find(nodeId);
    if (it != nodes_.end()) {
        it->second.lastSeen = std::chrono::steady_clock::now();
        
        if (!it->second.wasAlive) {
            // Node recovered
            it->second.wasAlive = true;
            
            std::lock_guard<std::mutex> statsLock(statsMutex_);
            stats_.nodeRecoveries++;
            
            if (nodeRecoveredCallback_) {
                nodeRecoveredCallback_(nodeId);
            }
        }
    }
    
    std::lock_guard<std::mutex> statsLock(statsMutex_);
    stats_.heartbeatsReceived++;
}

bool HeartbeatMonitor::IsNodeAlive(const std::string& nodeId) const {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    auto it = nodes_.find(nodeId);
    if (it == nodes_.end()) {
        return false;
    }
    
    auto now = std::chrono::steady_clock::now();
    return (now - it->second.lastSeen) < timeout_;
}

std::vector<std::string> HeartbeatMonitor::GetAliveNodes() const {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    std::vector<std::string> alive;
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& [id, hb] : nodes_) {
        if ((now - hb.lastSeen) < timeout_) {
            alive.push_back(id);
        }
    }
    
    return alive;
}

std::vector<std::string> HeartbeatMonitor::GetFailedNodes() const {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    std::vector<std::string> failed;
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& [id, hb] : nodes_) {
        if ((now - hb.lastSeen) >= timeout_) {
            failed.push_back(id);
        }
    }
    
    return failed;
}

std::chrono::milliseconds HeartbeatMonitor::GetLastHeartbeat(const std::string& nodeId) const {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    
    auto it = nodes_.find(nodeId);
    if (it == nodes_.end()) {
        return std::chrono::milliseconds(-1);
    }
    
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.lastSeen);
}

void HeartbeatMonitor::SetNodeFailedCallback(std::function<void(const std::string&)> callback) {
    nodeFailedCallback_ = callback;
}

void HeartbeatMonitor::SetNodeRecoveredCallback(std::function<void(const std::string&)> callback) {
    nodeRecoveredCallback_ = callback;
}

HeartbeatMonitor::Stats HeartbeatMonitor::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void HeartbeatMonitor::MonitorLoop() {
    while (running_.load()) {
        std::this_thread::sleep_for(interval_);
        
        std::lock_guard<std::mutex> lock(nodesMutex_);
        auto now = std::chrono::steady_clock::now();
        
        for (auto& [id, hb] : nodes_) {
            bool isAlive = (now - hb.lastSeen) < timeout_;
            
            if (hb.wasAlive && !isAlive) {
                // Node failed
                hb.wasAlive = false;
                
                std::lock_guard<std::mutex> statsLock(statsMutex_);
                stats_.nodeFailures++;
                
                if (nodeFailedCallback_) {
                    nodeFailedCallback_(id);
                }
            }
        }
    }
}

// ============================================================================
// CommunicationManager Implementation
// ============================================================================

CommunicationManager::CommunicationManager() = default;

CommunicationManager::~CommunicationManager() {
    Shutdown();
}

bool CommunicationManager::Initialize(const DiscoveryConfig& config) {
    config_ = config;
    
    messageBus_ = std::make_unique<MessageBus>();
    if (!messageBus_->Initialize(config)) {
        return false;
    }
    
    heartbeatMonitor_ = std::make_unique<HeartbeatMonitor>();
    if (!heartbeatMonitor_->Initialize(
        std::chrono::milliseconds(1000),  // 1 second interval
        std::chrono::milliseconds(5000))) { // 5 second timeout
        return false;
    }
    
    // Setup callbacks
    heartbeatMonitor_->SetNodeFailedCallback([this](const std::string& nodeId) {
        std::cout << "[CommunicationManager] Node failed: " << nodeId << "\n";
        messageBus_->DisconnectFromNode(nodeId);
    });
    
    std::cout << "[CommunicationManager] Initialized\n";
    return true;
}

void CommunicationManager::Shutdown() {
    if (messageBus_) {
        messageBus_->Shutdown();
        messageBus_.reset();
    }
    
    if (heartbeatMonitor_) {
        heartbeatMonitor_->Shutdown();
        heartbeatMonitor_.reset();
    }
}

void CommunicationManager::OnNodeDiscovered(const NodeInfo& node) {
    // Connect to newly discovered node
    if (!messageBus_->IsConnectedTo(node.nodeId)) {
        if (messageBus_->ConnectToNode(node)) {
            heartbeatMonitor_->RegisterNode(node.nodeId);
        }
    }
}

void CommunicationManager::OnNodeLeft(const std::string& nodeId) {
    heartbeatMonitor_->UnregisterNode(nodeId);
    messageBus_->DisconnectFromNode(nodeId);
}

bool CommunicationManager::SendToNode(const std::string& nodeId, const Message& msg) {
    return messageBus_->SendToNode(nodeId, msg);
}

bool CommunicationManager::Broadcast(const Message& msg) {
    return messageBus_->Broadcast(msg);
}

bool CommunicationManager::RpcCall(const std::string& nodeId, const std::string& method,
                                  const std::vector<uint8_t>& params, std::vector<uint8_t>& result) {
    RpcRequest request;
    request.method = method;
    request.params = params;
    request.requestId = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    request.timeout = std::chrono::milliseconds(5000);
    
    RpcResponse response;
    if (!messageBus_->RpcCall(nodeId, request, response)) {
        return false;
    }
    
    result = response.result;
    return response.success;
}

void CommunicationManager::PublishEvent(const std::string& eventType, const std::vector<uint8_t>& data) {
    messageBus_->PublishEvent(eventType, data);
}

void CommunicationManager::Subscribe(const std::string& eventType,
                                    std::function<void(const std::string&, const std::vector<uint8_t>&)> handler) {
    messageBus_->SubscribeToEvent(eventType, handler);
}

bool CommunicationManager::IsNodeReachable(const std::string& nodeId) const {
    return messageBus_->IsConnectedTo(nodeId) && heartbeatMonitor_->IsNodeAlive(nodeId);
}

std::vector<std::string> CommunicationManager::GetReachableNodes() const {
    auto connected = messageBus_->GetConnectedNodes();
    std::vector<std::string> reachable;
    
    for (const auto& nodeId : connected) {
        if (heartbeatMonitor_->IsNodeAlive(nodeId)) {
            reachable.push_back(nodeId);
        }
    }
    
    return reachable;
}

void CommunicationManager::PrintStats() const {
    auto busStats = messageBus_->GetStats();
    auto hbStats = heartbeatMonitor_->GetStats();
    
    std::cout << "\n=== Communication Manager Statistics ===\n";
    std::cout << "Active Connections: " << busStats.activeConnections << "\n";
    std::cout << "Messages Sent: " << busStats.totalMessagesSent << "\n";
    std::cout << "Messages Received: " << busStats.totalMessagesReceived << "\n";
    std::cout << "Failed Sends: " << busStats.failedSends << "\n";
    std::cout << "Failed RPCs: " << busStats.failedRpcs << "\n";
    std::cout << "Heartbeats Received: " << hbStats.heartbeatsReceived << "\n";
    std::cout << "Node Failures: " << hbStats.nodeFailures << "\n";
    std::cout << "Node Recoveries: " << hbStats.nodeRecoveries << "\n";
    std::cout << "========================================\n";
}

} // namespace Distributed
