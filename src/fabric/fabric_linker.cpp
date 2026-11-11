//=============================================================================
// Fabric Linker Implementation - VAL-031.3 2-Node PoC
// Session state machine with proper handshake
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
    , state_handler_(nullptr)
{
    memset(&wsa_data_, 0, sizeof(wsa_data_));
}

FabricLinker::~FabricLinker() {
    Shutdown();
}

const char* FabricLinker::StateToString(SessionState state) {
    switch (state) {
        case SessionState::DISCONNECTED:  return "DISCONNECTED";
        case SessionState::CONNECTING:    return "CONNECTING";
        case SessionState::HANDSHAKE:     return "HANDSHAKE";
        case SessionState::ESTABLISHED:   return "ESTABLISHED";
        case SessionState::ACTIVE:        return "ACTIVE";
        case SessionState::CLOSING:       return "CLOSING";
        default:                          return "UNKNOWN";
    }
}

void FabricLinker::SetState(SessionState new_state) {
    SessionState old_state = state_.exchange(new_state);
    if (old_state != new_state && state_handler_) {
        state_handler_(old_state, new_state);
    }
    printf("[FabricLinker] State: %s -> %s\n", 
           StateToString(old_state), StateToString(new_state));
}

bool FabricLinker::Initialize(const FabricConfig& config) {
    config_ = config;
    
    printf("[FabricLinker] Initializing Node %u...\n", config_.node_id);
    printf("[FabricLinker] Capabilities: 0x%016llX\n", config_.capabilities);
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
    SetState(SessionState::DISCONNECTED);
    printf("[FabricLinker] Ready\n");
    return true;
}

void FabricLinker::Shutdown() {
    printf("[FabricLinker] Shutting down...\n");
    
    shutdown_.store(true);
    
    // Send GOODBYE if established
    if (IsEstablished()) {
        Disconnect();
    }
    
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
    SetState(SessionState::DISCONNECTED);
    
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
    
    SetState(SessionState::CONNECTING);
    
    printf("[FabricLinker] Connecting to %s:%u...\n", 
           config_.peer_address, config_.peer_port);
    
    // Create socket
    peer_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (peer_socket_ == INVALID_SOCKET) {
        last_error_ = WSAGetLastError();
        printf("[FabricLinker] ERROR: socket() failed: %d\n", last_error_);
        SetState(SessionState::DISCONNECTED);
        return false;
    }
    
    // Set options
    if (!SetSocketOptions(peer_socket_)) {
        SetState(SessionState::DISCONNECTED);
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
        SetState(SessionState::DISCONNECTED);
        return false;
    }
    
    SetState(SessionState::HANDSHAKE);
    printf("[FabricLinker] TCP connected, starting handshake...\n");
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
    
    SetState(SessionState::CONNECTING);
    
    printf("[FabricLinker] Waiting for peer connection on port %u...\n", 
           config_.listen_port);
    
    // Accept connection
    sockaddr_in client_addr;
    int addr_len = sizeof(client_addr);
    peer_socket_ = accept(listen_socket_, (sockaddr*)&client_addr, &addr_len);
    
    if (peer_socket_ == INVALID_SOCKET) {
        last_error_ = WSAGetLastError();
        printf("[FabricLinker] ERROR: accept() failed: %d\n", last_error_);
        SetState(SessionState::DISCONNECTED);
        return false;
    }
    
    // Set options on peer socket
    if (!SetSocketOptions(peer_socket_)) {
        SetState(SessionState::DISCONNECTED);
        return false;
    }
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    printf("[FabricLinker] Peer connected from %s:%d\n", 
           client_ip, ntohs(client_addr.sin_port));
    
    SetState(SessionState::HANDSHAKE);
    printf("[FabricLinker] TCP connected, waiting for handshake...\n");
    return true;
}

bool FabricLinker::PerformHandshake() {
    if (state_.load() != SessionState::HANDSHAKE) {
        printf("[FabricLinker] ERROR: Not in HANDSHAKE state\n");
        return false;
    }
    
    printf("[FabricLinker] Performing B008 handshake...\n");
    
    if (config_.is_server) {
        // Server: wait for HELLO, send HELLO_ACK
        Packet hello;
        if (!ReceivePacket(hello, 10000)) {
            printf("[FabricLinker] ERROR: Did not receive HELLO\n");
            stats_.handshakes_failed.fetch_add(1);
            SetState(SessionState::DISCONNECTED);
            return false;
        }
        
        if (hello.header.opcode != static_cast<uint16_t>(Opcode::HELLO)) {
            printf("[FabricLinker] ERROR: Expected HELLO, got %d\n", 
                   hello.header.opcode);
            stats_.handshakes_failed.fetch_add(1);
            SetState(SessionState::DISCONNECTED);
            return false;
        }
        
        // Parse HELLO payload
        HelloPayload* hello_data = static_cast<HelloPayload*>(hello.payload);
        printf("[FabricLinker] Received HELLO from Node %u\n", hello_data->node_id);
        printf("[FabricLinker] Peer capabilities: 0x%016llX\n", hello_data->capabilities);
        
        // Store session info
        session_.peer_node_id = hello_data->node_id;
        session_.peer_capabilities = hello_data->capabilities & config_.capabilities;
        session_.max_packet_size = min(hello_data->max_packet_size, (uint32_t)65536);
        session_.heartbeat_interval_ms = hello_data->heartbeat_interval_ms;
        session_.session_id = 1;  // Server assigns session ID
        session_.established_time = GetTickCount64();
        
        // Send HELLO_ACK
        if (!SendHelloAck(0)) {
            printf("[FabricLinker] ERROR: Failed to send HELLO_ACK\n");
            stats_.handshakes_failed.fetch_add(1);
            SetState(SessionState::DISCONNECTED);
            return false;
        }
        
        printf("[FabricLinker] Sent HELLO_ACK (session=%u)\n", session_.session_id);
        
    } else {
        // Client: send HELLO, wait for HELLO_ACK
        if (!SendHello()) {
            printf("[FabricLinker] ERROR: Failed to send HELLO\n");
            stats_.handshakes_failed.fetch_add(1);
            SetState(SessionState::DISCONNECTED);
            return false;
        }
        
        printf("[FabricLinker] Sent HELLO\n");
        
        // Wait for HELLO_ACK
        Packet hello_ack;
        if (!ReceivePacket(hello_ack, 10000)) {
            printf("[FabricLinker] ERROR: Did not receive HELLO_ACK\n");
            stats_.handshakes_failed.fetch_add(1);
            SetState(SessionState::DISCONNECTED);
            return false;
        }
        
        if (hello_ack.header.opcode != static_cast<uint16_t>(Opcode::HELLO_ACK)) {
            printf("[FabricLinker] ERROR: Expected HELLO_ACK, got %d\n", 
                   hello_ack.header.opcode);
            stats_.handshakes_failed.fetch_add(1);
            SetState(SessionState::DISCONNECTED);
            return false;
        }
        
        // Parse HELLO_ACK payload
        HelloAckPayload* ack_data = static_cast<HelloAckPayload*>(hello_ack.payload);
        if (ack_data->status != 0) {
            printf("[FabricLinker] ERROR: HELLO_ACK status=%u\n", ack_data->status);
            stats_.handshakes_failed.fetch_add(1);
            SetState(SessionState::DISCONNECTED);
            return false;
        }
        
        // Store session info
        session_.session_id = ack_data->session_id;
        session_.peer_capabilities = ack_data->capabilities;
        session_.max_packet_size = ack_data->max_packet_size;
        session_.heartbeat_interval_ms = ack_data->heartbeat_interval_ms;
        session_.established_time = GetTickCount64();
        
        printf("[FabricLinker] Received HELLO_ACK (session=%u)\n", session_.session_id);
        printf("[FabricLinker] Negotiated capabilities: 0x%016llX\n", session_.peer_capabilities);
    }
    
    stats_.handshakes_completed.fetch_add(1);
    SetState(SessionState::ESTABLISHED);
    printf("[FabricLinker] Handshake complete - session established\n");
    return true;
}

bool FabricLinker::SendHello() {
    Packet hello;
    hello.InitHello(config_.node_id, config_.capabilities);
    bool result = SendPacket(hello);
    hello.Cleanup();
    return result;
}

bool FabricLinker::SendHelloAck(uint16_t status) {
    Packet ack;
    ack.InitHelloAck(session_.session_id, session_.peer_capabilities, status);
    bool result = SendPacket(ack);
    ack.Cleanup();
    return result;
}

bool FabricLinker::SendHeartbeat() {
    if (!IsEstablished()) {
        return false;
    }
    
    Packet ping;
    ping.InitPing(session_.session_id, session_.next_sequence++);
    bool result = SendPacket(ping);
    ping.Cleanup();
    return result;
}

bool FabricLinker::SendPong(uint32_t seq, uint64_t ping_timestamp) {
    Packet pong;
    pong.InitPong(session_.session_id, seq, ping_timestamp);
    bool result = SendPacket(pong);
    pong.Cleanup();
    return result;
}

bool FabricLinker::SendError(FabricError code, const char* msg) {
    Packet err;
    err.InitError(code, session_.next_sequence, msg);
    bool result = SendPacket(err);
    err.Cleanup();
    return result;
}

bool FabricLinker::Disconnect() {
    if (!IsEstablished()) {
        return true;
    }
    
    SetState(SessionState::CLOSING);
    
    // Send GOODBYE
    Packet goodbye;
    goodbye.InitGoodbye(session_.session_id, session_.next_sequence++);
    SendPacket(goodbye);
    goodbye.Cleanup();
    
    printf("[FabricLinker] Sent GOODBYE\n");
    SetState(SessionState::DISCONNECTED);
    return true;
}

bool FabricLinker::ProcessPacket(Packet& packet) {
    // Verify packet integrity
    if (!packet.Verify()) {
        printf("[FabricLinker] ERROR: Packet verification failed\n");
        stats_.crc_failures.fetch_add(1);
        return false;
    }
    
    Opcode op = static_cast<Opcode>(packet.header.opcode);
    
    switch (op) {
        case Opcode::PING: {
            // Respond with PONG
            PingPayload* ping = static_cast<PingPayload*>(packet.payload);
            SendPong(packet.header.sequence, ping->timestamp);
            break;
        }
        
        case Opcode::PONG: {
            // Calculate RTT
            PingPayload* pong = static_cast<PingPayload*>(packet.payload);
            uint64_t now = GetTickCount64();
            uint64_t rtt = now - pong->timestamp;
            stats_.latency_sum.fetch_add(rtt * 1000); // Convert to us
            stats_.latency_count.fetch_add(1);
            break;
        }
        
        case Opcode::GOODBYE: {
            printf("[FabricLinker] Received GOODBYE from peer\n");
            SetState(SessionState::CLOSING);
            break;
        }
        
        case Opcode::ERROR: {
            ErrorPayload* err = static_cast<ErrorPayload*>(packet.payload);
            printf("[FabricLinker] Received ERROR: %s\n", err->message);
            stats_.errors.fetch_add(1);
            break;
        }
        
        default:
            printf("[FabricLinker] WARNING: Unhandled opcode %d\n", packet.header.opcode);
            break;
    }
    
    return true;
}

bool FabricLinker::SendPacket(const Packet& packet) {
    if (peer_socket_ == INVALID_SOCKET) {
        printf("[FabricLinker] ERROR: No peer connection\n");
        return false;
    }
    
    // Send header
    if (!SendAll(&packet.header, sizeof(packet.header))) {
        stats_.errors.fetch_add(1);
        return false;
    }
    
    // Send payload if present
    if (packet.payload && packet.header.payload_size > 0) {
        if (!SendAll(packet.payload, packet.header.payload_size)) {
            stats_.errors.fetch_add(1);
            return false;
        }
    }
    
    stats_.packets_sent.fetch_add(1);
    stats_.bytes_sent.fetch_add(sizeof(packet.header) + packet.header.payload_size);
    
    return true;
}

bool FabricLinker::ReceivePacket(Packet& out_packet, int timeout_ms) {
    if (peer_socket_ == INVALID_SOCKET) {
        printf("[FabricLinker] ERROR: No peer connection\n");
        return false;
    }
    
    // Receive header
    if (!RecvAll(&out_packet.header, sizeof(out_packet.header), timeout_ms)) {
        return false;
    }
    
    stats_.packets_recv.fetch_add(1);
    stats_.bytes_recv.fetch_add(sizeof(out_packet.header));
    
    // Verify magic
    if (!out_packet.header.IsValidMagic()) {
        printf("[FabricLinker] ERROR: Invalid magic: 0x%08X\n", out_packet.header.magic);
        stats_.errors.fetch_add(1);
        return false;
    }
    
    // Verify version
    if (!out_packet.header.IsVersionCompatible()) {
        printf("[FabricLinker] ERROR: Version mismatch: %u vs %u\n", 
               out_packet.header.version, B008_PROTOCOL_VERSION);
        stats_.version_mismatches.fetch_add(1);
        return false;
    }
    
    // Receive payload if present
    if (out_packet.header.payload_size > 0) {
        out_packet.payload = new uint8_t[out_packet.header.payload_size];
        if (!RecvAll(out_packet.payload, out_packet.header.payload_size, timeout_ms)) {
            delete[] static_cast<uint8_t*>(out_packet.payload);
            out_packet.payload = nullptr;
            return false;
        }
        stats_.bytes_recv.fetch_add(out_packet.header.payload_size);
    }
    
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
            SetState(SessionState::DISCONNECTED);
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
