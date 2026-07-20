//=============================================================================
// Fabric Linker Implementation - VAL-031.3 2-Node PoC
// Raw Win32 socket transport
//=============================================================================

#include "fabric_linker.hpp"
#include <cstdio>
#include <cstring>

namespace RawrXD {
namespace Fabric {

//=============================================================================
// FabricLinker Implementation
//=============================================================================

FabricLinker::FabricLinker()
    : listen_socket_(INVALID_SOCKET)
    , peer_socket_(INVALID_SOCKET)
    , last_error_(0)
{
    memset(&wsa_data_, 0, sizeof(wsa_data_));
}

FabricLinker::~FabricLinker() {
    Shutdown();
}

bool FabricLinker::Initialize(const FabricConfig& config) {
    config_ = config;
    
    printf("[FabricLinker] Initializing Node %u...\n", config_.node_id);
    printf("[FabricLinker] Mode: %s\n", config_.is_server ? "SERVER" : "CLIENT");
    
    // Initialize WinSock
    if (!InitWinSock()) {
        return false;
    }
    
    // Create listen socket if server
    if (config_.is_server) {
        if (!CreateListenSocket()) {
            return false;
        }
    }
    
    initialized_.store(true);
    printf("[FabricLinker] Ready\n");
    return true;
}

void FabricLinker::Shutdown() {
    printf("[FabricLinker] Shutting down...\n");
    
    shutdown_.store(true);
    
    // Close sockets
    if (peer_socket_ != INVALID_SOCKET) {
        closesocket(peer_socket_);
        peer_socket_ = INVALID_SOCKET;
    }
    
    if (listen_socket_ != INVALID_SOCKET) {
        closesocket(listen_socket_);
        listen_socket_ = INVALID_SOCKET;
    }
    
    // Cleanup WinSock
    if (initialized_.load()) {
        WSACleanup();
    }
    
    initialized_.store(false);
    connected_.store(false);
    
    printf("[FabricLinker] Shutdown complete\n");
}

bool FabricLinker::ConnectToPeer() {
    if (!initialized_.load()) {
        printf("[FabricLinker] ERROR: Not initialized\n");
        return false;
    }
    
    if (config_.is_server) {
        printf("[FabricLinker] ERROR: Server mode cannot connect\n");
        return false;
    }
    
    printf("[FabricLinker] Connecting to %s:%u...\n", 
           config_.peer_address, config_.peer_port);
    
    // Create socket
    peer_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (peer_socket_ == INVALID_SOCKET) {
        last_error_ = WSAGetLastError();
        printf("[FabricLinker] ERROR: socket() failed: %d\n", last_error_);
        return false;
    }
    
    // Set options
    if (!SetSocketOptions(peer_socket_)) {
        return false;
    }
    
    // Connect
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.peer_port);
    inet_pton(AF_INET, config_.peer_address, &addr.sin_addr);
    
    if (connect(peer_socket_, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        last_error_ = WSAGetLastError();
        printf("[FabricLinker] ERROR: connect() failed: %d\n", last_error_);
        closesocket(peer_socket_);
        peer_socket_ = INVALID_SOCKET;
        return false;
    }
    
    connected_.store(true);
    printf("[FabricLinker] Connected to peer\n");
    return true;
}

bool FabricLinker::AcceptPeer() {
    if (!initialized_.load()) {
        printf("[FabricLinker] ERROR: Not initialized\n");
        return false;
    }
    
    if (!config_.is_server) {
        printf("[FabricLinker] ERROR: Client mode cannot accept\n");
        return false;
    }
    
    printf("[FabricLinker] Waiting for peer connection on port %u...\n", 
           config_.listen_port);
    
    // Accept connection
    sockaddr_in client_addr;
    int addr_len = sizeof(client_addr);
    peer_socket_ = accept(listen_socket_, (sockaddr*)&client_addr, &addr_len);
    
    if (peer_socket_ == INVALID_SOCKET) {
        last_error_ = WSAGetLastError();
        printf("[FabricLinker] ERROR: accept() failed: %d\n", last_error_);
        return false;
    }
    
    // Set options on peer socket
    if (!SetSocketOptions(peer_socket_)) {
        return false;
    }
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    printf("[FabricLinker] Peer connected from %s:%d\n", 
           client_ip, ntohs(client_addr.sin_port));
    
    connected_.store(true);
    return true;
}

bool FabricLinker::SendPacket(const Packet& packet) {
    return SendPacketWithPayload(packet, nullptr, 0);
}

bool FabricLinker::SendPacketWithPayload(const Packet& packet, 
                                          const void* payload, 
                                          size_t len) {
    if (!connected_.load()) {
        printf("[FabricLinker] ERROR: Not connected\n");
        return false;
    }
    
    // Send header
    if (!SendAll(&packet.header, sizeof(packet.header))) {
        stats_.errors.fetch_add(1);
        return false;
    }
    
    // Send payload if present
    if (payload && len > 0) {
        if (!SendAll(payload, len)) {
            stats_.errors.fetch_add(1);
            return false;
        }
    }
    
    stats_.packets_sent.fetch_add(1);
    stats_.bytes_sent.fetch_add(sizeof(packet.header) + len);
    
    return true;
}

bool FabricLinker::ReceivePacket(Packet& out_packet, int timeout_ms) {
    if (!connected_.load()) {
        printf("[FabricLinker] ERROR: Not connected\n");
        return false;
    }
    
    // Receive header
    if (!RecvAll(&out_packet.header, sizeof(out_packet.header), timeout_ms)) {
        return false;
    }
    
    // Verify checksum
    if (!out_packet.header.VerifyChecksum()) {
        printf("[FabricLinker] ERROR: Checksum mismatch\n");
        stats_.errors.fetch_add(1);
        return false;
    }
    
    stats_.packets_recv.fetch_add(1);
    stats_.bytes_recv.fetch_add(sizeof(out_packet.header));
    
    return true;
}

bool FabricLinker::PerformHandshake() {
    printf("[FabricLinker] Performing handshake...\n");
    
    if (config_.is_server) {
        // Server: wait for PING, send PONG
        Packet ping;
        if (!ReceivePacket(ping, 10000)) {
            printf("[FabricLinker] ERROR: Did not receive PING\n");
            return false;
        }
        
        if (ping.header.command != static_cast<uint8_t>(PacketCmd::PING)) {
            printf("[FabricLinker] ERROR: Expected PING, got %d\n", 
                   ping.header.command);
            return false;
        }
        
        printf("[FabricLinker] Received PING from Node %u\n", ping.header.node_id);
        
        // Send PONG
        Packet pong;
        pong.InitPong(config_.node_id, ping.header.block_id);
        if (!SendPacket(pong)) {
            printf("[FabricLinker] ERROR: Failed to send PONG\n");
            return false;
        }
        
        printf("[FabricLinker] Sent PONG\n");
        
    } else {
        // Client: send PING, wait for PONG
        Packet ping;
        ping.InitPing(config_.node_id);
        
        auto start = GetTickCount64();
        
        if (!SendPacket(ping)) {
            printf("[FabricLinker] ERROR: Failed to send PING\n");
            return false;
        }
        
        printf("[FabricLinker] Sent PING\n");
        
        // Wait for PONG
        Packet pong;
        if (!ReceivePacket(pong, 10000)) {
            printf("[FabricLinker] ERROR: Did not receive PONG\n");
            return false;
        }
        
        if (pong.header.command != static_cast<uint8_t>(PacketCmd::PONG)) {
            printf("[FabricLinker] ERROR: Expected PONG, got %d\n", 
                   pong.header.command);
            return false;
        }
        
        auto latency = GetTickCount64() - start;
        stats_.latency_sum.fetch_add(latency * 1000); // Convert to us
        stats_.latency_count.fetch_add(1);
        
        printf("[FabricLinker] Received PONG from Node %u (latency: %llu ms)\n", 
               pong.header.node_id, latency);
    }
    
    printf("[FabricLinker] Handshake complete\n");
    return true;
}

//=============================================================================
// Private Helpers
//=============================================================================

bool FabricLinker::InitWinSock() {
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data_);
    if (result != 0) {
        printf("[FabricLinker] ERROR: WSAStartup failed: %d\n", result);
        return false;
    }
    
    printf("[FabricLinker] WinSock initialized: %s\n", wsa_data_.szDescription);
    return true;
}

bool FabricLinker::CreateListenSocket() {
    // Create socket
    listen_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket_ == INVALID_SOCKET) {
        last_error_ = WSAGetLastError();
        printf("[FabricLinker] ERROR: socket() failed: %d\n", last_error_);
        return false;
    }
    
    // Set options
    if (!SetSocketOptions(listen_socket_)) {
        return false;
    }
    
    // Allow address reuse
    int reuse = 1;
    setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR, 
               (char*)&reuse, sizeof(reuse));
    
    // Bind
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(config_.listen_port);
    
    if (bind(listen_socket_, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        last_error_ = WSAGetLastError();
        printf("[FabricLinker] ERROR: bind() failed: %d\n", last_error_);
        closesocket(listen_socket_);
        listen_socket_ = INVALID_SOCKET;
        return false;
    }
    
    // Listen
    if (listen(listen_socket_, 1) == SOCKET_ERROR) {
        last_error_ = WSAGetLastError();
        printf("[FabricLinker] ERROR: listen() failed: %d\n", last_error_);
        closesocket(listen_socket_);
        listen_socket_ = INVALID_SOCKET;
        return false;
    }
    
    printf("[FabricLinker] Listening on port %u\n", config_.listen_port);
    return true;
}

bool FabricLinker::SetSocketOptions(SOCKET sock) {
    // Disable Nagle's algorithm for low latency
    int nodelay = 1;
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, 
                   (char*)&nodelay, sizeof(nodelay)) == SOCKET_ERROR) {
        printf("[FabricLinker] WARNING: Failed to set TCP_NODELAY\n");
    }
    
    // Set send/receive buffer sizes
    int bufsize = 4 * 1024 * 1024; // 4MB
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(bufsize));
    
    // Set timeout
    DWORD timeout = 5000; // 5 seconds
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    return true;
}

bool FabricLinker::SendAll(const void* data, size_t len) {
    const char* ptr = static_cast<const char*>(data);
    size_t sent = 0;
    
    while (sent < len) {
        int result = ::send(peer_socket_, ptr + sent, 
                           static_cast<int>(len - sent), 0);
        if (result == SOCKET_ERROR) {
            last_error_ = WSAGetLastError();
            printf("[FabricLinker] ERROR: send() failed: %d\n", last_error_);
            return false;
        }
        sent += result;
    }
    
    return true;
}

bool FabricLinker::RecvAll(void* data, size_t len, int timeout_ms) {
    char* ptr = static_cast<char*>(data);
    size_t received = 0;
    
    // Set timeout
    DWORD timeout = static_cast<DWORD>(timeout_ms);
    setsockopt(peer_socket_, SOL_SOCKET, SO_RCVTIMEO, 
               (char*)&timeout, sizeof(timeout));
    
    while (received < len) {
        int result = recv(peer_socket_, ptr + received, 
                         static_cast<int>(len - received), 0);
        if (result == SOCKET_ERROR) {
            last_error_ = WSAGetLastError();
            if (last_error_ == WSAETIMEDOUT) {
                stats_.timeouts.fetch_add(1);
            }
            printf("[FabricLinker] ERROR: recv() failed: %d\n", last_error_);
            return false;
        }
        if (result == 0) {
            printf("[FabricLinker] ERROR: Connection closed by peer\n");
            connected_.store(false);
            return false;
        }
        received += result;
    }
    
    return true;
}

//=============================================================================
// Global Instance
//=============================================================================

FabricLinker& GetFabricLinker() {
    static FabricLinker instance;
    return instance;
}

} // namespace Fabric
} // namespace RawrXD
