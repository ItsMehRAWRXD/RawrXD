#pragma once
//=============================================================================
// Fabric Linker - VAL-031.3 2-Node PoC
// Raw Win32 socket transport with session state machine
//=============================================================================

#include "b008_packet.hpp"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <atomic>
#include <functional>
#include <string>

#pragma comment(lib, "ws2_32.lib")

namespace RawrXD {
namespace Fabric {

// Forward declarations
class FabricOrchestrator;

// Fabric configuration
struct FabricConfig {
    uint8_t node_id;            // This node's ID (0, 1, 2...)
    uint16_t listen_port;       // Port to listen on
    const char* peer_address;   // Peer node IP (for client mode)
    uint16_t peer_port;         // Peer node port
    bool is_server;             // True = listen, False = connect
    uint64_t capabilities;      // FabricCapability bitmask
    
    FabricConfig() 
        : node_id(0), listen_port(31337), 
          peer_address("127.0.0.1"), peer_port(31338),
          is_server(true),
          capabilities(CAP_AVX512 | CAP_IOCP | CAP_RESIDENCY_PLANNER) {}
};

// Session information
struct SessionInfo {
    uint32_t session_id;
    uint8_t peer_node_id;
    uint64_t peer_capabilities;
    uint32_t max_packet_size;
    uint32_t heartbeat_interval_ms;
    uint64_t established_time;
    uint32_t next_sequence;
    
    SessionInfo() 
        : session_id(0), peer_node_id(0), peer_capabilities(0),
          max_packet_size(65536), heartbeat_interval_ms(5000),
          established_time(0), next_sequence(1) {}
};

// Fabric statistics
struct FabricStats {
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_recv{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_recv{0};
    std::atomic<uint64_t> errors{0};
    std::atomic<uint64_t> timeouts{0};
    std::atomic<uint64_t> crc_failures{0};
    std::atomic<uint64_t> version_mismatches{0};
    
    // Latency tracking (microseconds)
    std::atomic<uint64_t> latency_sum{0};
    std::atomic<uint64_t> latency_count{0};
    
    // State transitions
    std::atomic<uint64_t> handshakes_completed{0};
    std::atomic<uint64_t> handshakes_failed{0};
    
    double GetAvgLatencyUs() const {
        uint64_t count = latency_count.load();
        if (count == 0) return 0.0;
        return static_cast<double>(latency_sum.load()) / count;
    }
};

// Fabric Linker - Raw socket transport with session management
class FabricLinker {
public:
    // Callback for state changes
    using StateChangeHandler = std::function<void(SessionState old_state, SessionState new_state)>;
    
    FabricLinker();
    ~FabricLinker();
    
    // Initialize WinSock and create sockets
    bool Initialize(const FabricConfig& config);
    
    // Shutdown and cleanup
    void Shutdown();
    
    // Connect to peer (client mode)
    bool ConnectToPeer();
    
    // Accept peer connection (server mode)
    bool AcceptPeer();
    
    // Perform full handshake (HELLO/HELLO_ACK)
    bool PerformHandshake();
    
    // Send heartbeat (PING)
    bool SendHeartbeat();
    
    // Process incoming packet (should be called in receive loop)
    bool ProcessPacket(Packet& packet);
    
    // Send packet
    bool SendPacket(const Packet& packet);
    
    // Receive packet (blocking, timeout_ms)
    bool ReceivePacket(Packet& out_packet, int timeout_ms = 5000);
    
    // Graceful disconnect
    bool Disconnect();
    
    // Get current session state
    SessionState GetState() const { return state_.load(); }
    
    // Check if session is established
    bool IsEstablished() const { return state_.load() == SessionState::ESTABLISHED || 
                                          state_.load() == SessionState::ACTIVE; }
    
    // Get session info
    SessionInfo GetSessionInfo() const { return session_; }
    
    // Get statistics
    FabricStats GetStats() const { return stats_; }
    
    // Get last error
    int GetLastError() const { return last_error_; }
    
    // Get state as string
    static const char* StateToString(SessionState state);
    
    // Set state change callback
    void SetStateChangeHandler(StateChangeHandler handler) { state_handler_ = handler; }
    
private:
    FabricConfig config_;
    SessionInfo session_;
    
    // Sockets
    SOCKET listen_socket_;
    SOCKET peer_socket_;
    
    // State
    std::atomic<SessionState> state_{SessionState::DISCONNECTED};
    std::atomic<bool> initialized_{false};
    std::atomic<bool> shutdown_{false};
    
    // Statistics
    FabricStats stats_;
    
    // Last error
    int last_error_;
    
    // WSADATA for WinSock
    WSADATA wsa_data_;
    
    // State change handler
    StateChangeHandler state_handler_;
    
    // Helper methods
    bool InitWinSock();
    bool CreateListenSocket();
    bool SetSocketOptions(SOCKET sock);
    bool SendAll(const void* data, size_t len);
    bool RecvAll(void* data, size_t len, int timeout_ms);
    void SetState(SessionState new_state);
    bool SendHello();
    bool SendHelloAck(uint16_t status = 0);
    bool SendPong(uint32_t seq, uint64_t ping_timestamp);
    bool SendError(FabricError code, const char* msg);
};

// Global fabric linker instance
FabricLinker& GetFabricLinker();

} // namespace Fabric
} // namespace RawrXD
