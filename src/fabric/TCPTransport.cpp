#include "TCPTransport.h"
#include <cstring>
#include <chrono>

namespace RawrXD {
namespace Fabric {

// ============================================================================
// TCPConnection Implementation
// ============================================================================

TCPConnection::TCPConnection() 
    : socket(INVALID_SOCKET)
    , nodeId(0)
    , recvHead(0)
    , recvTail(0)
    , sendPending(false) {
    memset(&recvOverlap, 0, sizeof(recvOverlap));
    memset(&sendOverlap, 0, sizeof(sendOverlap));
    memset(recvBuffer, 0, sizeof(recvBuffer));
}

TCPConnection::~TCPConnection() {
    Close();
}

bool TCPConnection::Initialize(SOCKET sock, uint32_t node) {
    socket = sock;
    nodeId = node;
    
    // Setup receive buffer descriptor
    recvBuf.buf = reinterpret_cast<char*>(recvBuffer);
    recvBuf.len = RECV_BUF_SIZE;
    
    connected.store(true, std::memory_order_release);
    return true;
}

void TCPConnection::Close() {
    if (socket != INVALID_SOCKET) {
        closing.store(true, std::memory_order_release);
        shutdown(socket, SD_BOTH);
        closesocket(socket);
        socket = INVALID_SOCKET;
    }
    connected.store(false, std::memory_order_release);
}

size_t TCPConnection::GetRecvAvailable() const {
    if (recvTail >= recvHead) {
        return recvTail - recvHead;
    } else {
        return (RECV_BUF_SIZE - recvHead) + recvTail;
    }
}

bool TCPConnection::AppendRecvData(const void* data, size_t len) {
    const uint8_t* src = static_cast<const uint8_t*>(data);
    
    for (size_t i = 0; i < len; i++) {
        size_t nextTail = (recvTail + 1) % RECV_BUF_SIZE;
        if (nextTail == recvHead) {
            return false;  // Buffer full
        }
        recvBuffer[recvTail] = src[i];
        recvTail = nextTail;
    }
    return true;
}

bool TCPConnection::ExtractMessage(FabricMessage& msg) {
    constexpr size_t MSG_SIZE = sizeof(FabricMessage);
    
    if (GetRecvAvailable() < MSG_SIZE) {
        return false;  // Not enough data
    }
    
    // Extract message from circular buffer
    uint8_t* dst = reinterpret_cast<uint8_t*>(&msg);
    for (size_t i = 0; i < MSG_SIZE; i++) {
        dst[i] = recvBuffer[recvHead];
        recvHead = (recvHead + 1) % RECV_BUF_SIZE;
    }
    
    return true;
}

// ============================================================================
// TCPTransport Implementation
// ============================================================================

TCPTransport::TCPTransport()
    : localNodeId_(0)
    , initialized_(false)
    , shutdown_(false)
    , hIOCP_(nullptr)
    , listenSocket_(INVALID_SOCKET)
    , listenPort_(0)
    , hAcceptThread_(nullptr)
    , messageHandler_(nullptr)
    , errorHandler_(nullptr) {
    memset(&wsaData_, 0, sizeof(wsaData_));
}

TCPTransport::~TCPTransport() {
    Shutdown();
}

bool TCPTransport::Initialize(uint32_t nodeId) {
    if (initialized_) {
        return false;
    }
    
    localNodeId_ = nodeId;
    
    // Initialize Winsock
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData_);
    if (result != 0) {
        return false;
    }
    
    // Create IOCP
    hIOCP_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, NUM_WORKERS);
    if (!hIOCP_) {
        WSACleanup();
        return false;
    }
    
    // Start worker threads
    shutdown_ = false;
    for (int i = 0; i < NUM_WORKERS; i++) {
        HANDLE hThread = CreateThread(nullptr, 0, WorkerThreadProc, this, 0, nullptr);
        if (hThread) {
            workerThreads_.push_back(hThread);
        }
    }
    
    initialized_ = true;
    return true;
}

void TCPTransport::Shutdown() {
    if (!initialized_) {
        return;
    }
    
    shutdown_ = true;
    
    // Signal IOCP to wake workers
    for (int i = 0; i < NUM_WORKERS; i++) {
        PostQueuedCompletionStatus(hIOCP_, 0, 0, nullptr);
    }
    
    // Close all connections
    {
        std::unique_lock<std::shared_mutex> lock(connectionsMutex_);
        for (auto& [nodeId, conn] : connections_) {
            if (conn) {
                conn->Close();
            }
        }
        connections_.clear();
    }
    
    // Close listen socket
    if (listenSocket_ != INVALID_SOCKET) {
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
    }
    
    // Wait for accept thread
    if (hAcceptThread_) {
        WaitForSingleObject(hAcceptThread_, 5000);
        CloseHandle(hAcceptThread_);
        hAcceptThread_ = nullptr;
    }
    
    // Wait for workers
    for (auto& hThread : workerThreads_) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }
    workerThreads_.clear();
    
    // Close IOCP
    if (hIOCP_) {
        CloseHandle(hIOCP_);
        hIOCP_ = nullptr;
    }
    
    // Cleanup Winsock
    WSACleanup();
    
    initialized_ = false;
}

bool TCPTransport::Listen(const char* bindAddress, uint16_t port) {
    if (!initialized_) {
        return false;
    }
    
    // Create listen socket
    listenSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket_ == INVALID_SOCKET) {
        return false;
    }
    
    // Enable address reuse
    int reuse = 1;
    setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, 
               reinterpret_cast<const char*>(&reuse), sizeof(reuse));
    
    // Bind
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, bindAddress, &addr.sin_addr);
    
    if (bind(listenSocket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
        return false;
    }
    
    // Listen
    if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
        return false;
    }
    
    listenPort_ = port;
    
    // Associate with IOCP
    CreateIoCompletionPort(reinterpret_cast<HANDLE>(listenSocket_), hIOCP_, 0, 0);
    
    // Start accept thread
    hAcceptThread_ = CreateThread(nullptr, 0, AcceptThreadProc, this, 0, nullptr);
    if (!hAcceptThread_) {
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
        return false;
    }
    
    return true;
}

bool TCPTransport::ConnectToNode(uint32_t nodeId, const char* address) {
    if (!initialized_) {
        return false;
    }
    
    // Parse address (format: "host:port")
    std::string addrStr(address);
    size_t colonPos = addrStr.find(':');
    if (colonPos == std::string::npos) {
        return false;
    }
    
    std::string host = addrStr.substr(0, colonPos);
    uint16_t port = static_cast<uint16_t>(std::stoi(addrStr.substr(colonPos + 1)));
    
    // Create socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return false;
    }
    
    // Connect
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    
    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }
    
    // Create connection
    auto conn = std::make_unique<TCPConnection>();
    conn->Initialize(sock, nodeId);
    
    // Associate with IOCP
    CreateIoCompletionPort(reinterpret_cast<HANDLE>(sock), hIOCP_, 
                          reinterpret_cast<ULONG_PTR>(conn.get()), 0);
    
    // Store connection
    {
        std::unique_lock<std::shared_mutex> lock(connectionsMutex_);
        connections_[nodeId] = std::move(conn);
    }
    
    // Start receiving
    auto it = connections_.find(nodeId);
    if (it != connections_.end()) {
        PostReceive(it->second.get());
    }
    
    return true;
}

void TCPTransport::DisconnectNode(uint32_t nodeId) {
    std::unique_lock<std::shared_mutex> lock(connectionsMutex_);
    
    auto it = connections_.find(nodeId);
    if (it != connections_.end() && it->second) {
        it->second->Close();
        connections_.erase(it);
    }
}

bool TCPTransport::IsConnected(uint32_t nodeId) {
    std::shared_lock<std::shared_mutex> lock(connectionsMutex_);
    
    auto it = connections_.find(nodeId);
    if (it == connections_.end() || !it->second) {
        return false;
    }
    
    return it->second->connected.load(std::memory_order_acquire);
}

bool TCPTransport::Send(uint32_t dstNodeId, const FabricMessage& msg) {
    if (!initialized_) {
        return false;
    }
    
    TCPConnection* conn = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(connectionsMutex_);
        auto it = connections_.find(dstNodeId);
        if (it == connections_.end() || !it->second) {
            if (errorHandler_) {
                errorHandler_(dstNodeId, "Node not connected");
            }
            return false;
        }
        conn = it->second.get();
    }
    
    if (!conn->connected.load(std::memory_order_acquire)) {
        return false;
    }
    
    // Prepare message
    FabricMessage msgCopy = msg;
    msgCopy.header.srcNodeId = localNodeId_;
    msgCopy.header.dstNodeId = dstNodeId;
    msgCopy.header.timestamp = GetTimestampUs();
    msgCopy.header.sequence = sequenceCounter_.fetch_add(1, std::memory_order_relaxed);
    msgCopy.header.payloadSize = sizeof(msgCopy.payload);
    msgCopy.header.checksum = CalculateCRC32(&msgCopy.payload, sizeof(msgCopy.payload));
    
    // Queue send
    {
        std::lock_guard<std::mutex> lock(conn->sendMutex);
        conn->sendQueue.push_back(msgCopy);
        
        if (!conn->sendPending) {
            conn->sendPending = true;
            return PostSend(conn, conn->sendQueue[0]);
        }
    }
    
    return true;
}

bool TCPTransport::Broadcast(const FabricMessage& msg) {
    std::shared_lock<std::shared_mutex> lock(connectionsMutex_);
    
    bool allSent = true;
    for (const auto& [nodeId, conn] : connections_) {
        if (!Send(nodeId, msg)) {
            allSent = false;
        }
    }
    
    return allSent;
}

void TCPTransport::SetMessageHandler(MessageHandler handler) {
    messageHandler_ = handler;
}

void TCPTransport::SetErrorHandler(ErrorHandler handler) {
    errorHandler_ = handler;
}

uint64_t TCPTransport::GetBytesSent() const {
    return bytesSent_.load(std::memory_order_relaxed);
}

uint64_t TCPTransport::GetBytesReceived() const {
    return bytesReceived_.load(std::memory_order_relaxed);
}

uint64_t TCPTransport::GetMessagesSent() const {
    return messagesSent_.load(std::memory_order_relaxed);
}

uint64_t TCPTransport::GetMessagesReceived() const {
    return messagesReceived_.load(std::memory_order_relaxed);
}

uint32_t TCPTransport::GetLatencyUs() const {
    uint64_t total = totalLatencyUs_.load(std::memory_order_relaxed);
    uint64_t count = latencyCount_.load(std::memory_order_relaxed);
    return count > 0 ? static_cast<uint32_t>(total / count) : 0;
}

bool TCPTransport::SetNagle(bool enabled) {
    // Apply to all connections
    std::shared_lock<std::shared_mutex> lock(connectionsMutex_);
    
    for (auto& [nodeId, conn] : connections_) {
        if (conn && conn->socket != INVALID_SOCKET) {
            int flag = enabled ? 0 : 1;
            setsockopt(conn->socket, IPPROTO_TCP, TCP_NODELAY,
                      reinterpret_cast<const char*>(&flag), sizeof(flag));
        }
    }
    return true;
}

bool TCPTransport::SetBufferSizes(int sendSize, int recvSize) {
    std::shared_lock<std::shared_mutex> lock(connectionsMutex_);
    
    for (auto& [nodeId, conn] : connections_) {
        if (conn && conn->socket != INVALID_SOCKET) {
            setsockopt(conn->socket, SOL_SOCKET, SO_SNDBUF,
                      reinterpret_cast<const char*>(&sendSize), sizeof(sendSize));
            setsockopt(conn->socket, SOL_SOCKET, SO_RCVBUF,
                      reinterpret_cast<const char*>(&recvSize), sizeof(recvSize));
        }
    }
    return true;
}

// ============================================================================
// Worker Thread
// ============================================================================

DWORD WINAPI TCPTransport::WorkerThreadProc(LPVOID param) {
    auto* transport = static_cast<TCPTransport*>(param);
    transport->WorkerLoop();
    return 0;
}

void TCPTransport::WorkerLoop() {
    DWORD bytesTransferred;
    ULONG_PTR completionKey;
    LPOVERLAPPED overlap;
    
    while (!shutdown_) {
        BOOL result = GetQueuedCompletionStatus(
            hIOCP_,
            &bytesTransferred,
            &completionKey,
            &overlap,
            INFINITE
        );
        
        if (!result) {
            if (shutdown_) break;
            continue;
        }
        
        if (completionKey == 0 && overlap == nullptr) {
            // Shutdown signal
            break;
        }
        
        auto* ctx = reinterpret_cast<IOCPContext*>(
            reinterpret_cast<uint8_t*>(overlap) - offsetof(IOCPContext, overlap)
        );
        
        switch (ctx->opType) {
            case IOCPOpType::RECEIVE:
                OnReceiveComplete(ctx, bytesTransferred);
                break;
            case IOCPOpType::SEND:
                OnSendComplete(ctx, bytesTransferred);
                break;
            case IOCPOpType::ACCEPT:
                OnAcceptComplete(ctx, bytesTransferred);
                break;
            case IOCPOpType::CONNECT:
                OnConnectComplete(ctx, bytesTransferred);
                break;
        }
    }
}

// ============================================================================
// Accept Thread
// ============================================================================

DWORD WINAPI TCPTransport::AcceptThreadProc(LPVOID param) {
    auto* transport = static_cast<TCPTransport*>(param);
    transport->AcceptLoop();
    return 0;
}

void TCPTransport::AcceptLoop() {
    while (!shutdown_ && listenSocket_ != INVALID_SOCKET) {
        sockaddr_in clientAddr;
        int addrLen = sizeof(clientAddr);
        
        SOCKET clientSock = accept(listenSocket_, 
                                   reinterpret_cast<sockaddr*>(&clientAddr), 
                                   &addrLen);
        
        if (clientSock == INVALID_SOCKET) {
            if (shutdown_) break;
            continue;
        }
        
        // Create connection (node ID will be assigned via handshake)
        auto conn = std::make_unique<TCPConnection>();
        conn->Initialize(clientSock, 0);  // Node ID 0 = unknown until handshake
        
        // Associate with IOCP
        CreateIoCompletionPort(reinterpret_cast<HANDLE>(clientSock), hIOCP_,
                              reinterpret_cast<ULONG_PTR>(conn.get()), 0);
        
        // Store temporarily (will be moved to proper node ID after handshake)
        {
            std::unique_lock<std::shared_mutex> lock(connectionsMutex_);
            connections_[0] = std::move(conn);
        }
        
        // Start receiving
        auto it = connections_.find(0);
        if (it != connections_.end()) {
            PostReceive(it->second.get());
        }
    }
}

// ============================================================================
// IOCP Operations
// ============================================================================

bool TCPTransport::PostReceive(TCPConnection* conn) {
    if (!conn || conn->socket == INVALID_SOCKET) {
        return false;
    }
    
    auto* ctx = new IOCPContext(IOCPOpType::RECEIVE);
    ctx->connection = conn;
    ctx->buffer = conn->recvBuf;
    
    DWORD flags = 0;
    DWORD bytesRecv = 0;
    
    int result = WSARecv(conn->socket, &ctx->buffer, 1, &bytesRecv, &flags,
                        &ctx->overlap, nullptr);
    
    if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        delete ctx;
        return false;
    }
    
    return true;
}

bool TCPTransport::PostSend(TCPConnection* conn, const FabricMessage& msg) {
    if (!conn || conn->socket == INVALID_SOCKET) {
        return false;
    }
    
    auto* ctx = new IOCPContext(IOCPOpType::SEND);
    ctx->connection = conn;
    ctx->buffer.buf = reinterpret_cast<char*>(const_cast<FabricMessage*>(&msg));
    ctx->buffer.len = sizeof(FabricMessage);
    
    DWORD bytesSent = 0;
    
    int result = WSASend(conn->socket, &ctx->buffer, 1, &bytesSent, 0,
                        &ctx->overlap, nullptr);
    
    if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        delete ctx;
        return false;
    }
    
    return true;
}

void TCPTransport::OnReceiveComplete(IOCPContext* ctx, DWORD bytes) {
    if (!ctx || !ctx->connection) {
        delete ctx;
        return;
    }
    
    TCPConnection* conn = ctx->connection;
    
    if (bytes == 0) {
        // Connection closed
        CloseConnection(conn);
        delete ctx;
        return;
    }
    
    // Update stats
    bytesReceived_.fetch_add(bytes, std::memory_order_relaxed);
    
    // Process received data
    // In production: append to circular buffer, extract messages
    // For now: direct message extraction (simplified)
    
    if (bytes >= sizeof(FabricMessage)) {
        FabricMessage* msg = reinterpret_cast<FabricMessage*>(conn->recvBuf.buf);
        
        // Validate checksum
        uint32_t expectedCRC = CalculateCRC32(&msg->payload, msg->header.payloadSize);
        if (expectedCRC == msg->header.checksum) {
            messagesReceived_.fetch_add(1, std::memory_order_relaxed);
            
            // Calculate latency
            uint64_t now = GetTimestampUs();
            uint64_t latency = now - msg->header.timestamp;
            totalLatencyUs_.fetch_add(latency, std::memory_order_relaxed);
            latencyCount_.fetch_add(1, std::memory_order_relaxed);
            
            // Deliver to handler
            if (messageHandler_) {
                messageHandler_(*msg, conn->nodeId);
            }
        }
    }
    
    // Repost receive
    PostReceive(conn);
    
    delete ctx;
}

void TCPTransport::OnSendComplete(IOCPContext* ctx, DWORD bytes) {
    if (!ctx || !ctx->connection) {
        delete ctx;
        return;
    }
    
    TCPConnection* conn = ctx->connection;
    
    if (bytes > 0) {
        bytesSent_.fetch_add(bytes, std::memory_order_relaxed);
        messagesSent_.fetch_add(1, std::memory_order_relaxed);
    }
    
    // Process next in queue
    {
        std::lock_guard<std::mutex> lock(conn->sendMutex);
        if (!conn->sendQueue.empty()) {
            conn->sendQueue.erase(conn->sendQueue.begin());
        }
        
        if (!conn->sendQueue.empty()) {
            PostSend(conn, conn->sendQueue[0]);
        } else {
            conn->sendPending = false;
        }
    }
    
    delete ctx;
}

void TCPTransport::OnAcceptComplete(IOCPContext* ctx, DWORD bytes) {
    // Handled in AcceptLoop for now
    delete ctx;
}

void TCPTransport::OnConnectComplete(IOCPContext* ctx, DWORD bytes) {
    delete ctx;
}

void TCPTransport::CloseConnection(TCPConnection* conn) {
    if (!conn) return;
    
    conn->Close();
    
    if (errorHandler_) {
        errorHandler_(conn->nodeId, "Connection closed");
    }
}

// ============================================================================
// Helpers
// ============================================================================

uint32_t TCPTransport::CalculateCRC32(const void* data, size_t len) {
    // Simple FNV-1a hash
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 16777619u;
    }
    return hash;
}

uint64_t TCPTransport::GetTimestampUs() const {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (count.QuadPart * 1000000) / freq.QuadPart;
}

// Factory function
FabricTransport* CreateTCPTransport() {
    return new TCPTransport();
}

} // namespace Fabric
} // namespace RawrXD
